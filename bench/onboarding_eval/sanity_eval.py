#!/usr/bin/env python3
"""sanity_eval.py — offline SLM sanity numbers for the onboarding candidate loop.

For each corpus (acmegw, zenwall, newapp): split the lines 5/15 via
onboarding's assign_roles (the exact production logic), then --runs times
per corpus run generate_candidate + validate_candidate against a LIVE Ollama
endpoint (the same OllamaClient the onboarding service uses). Tally per
corpus: valid-JSON rate, compiles rate, held-out match rate, mean attempts,
wall-clock per rule; print a markdown table and optionally --write the
docs/m2-slm-sanity.md page (measured numbers only — model tag, host CPU,
date, run count in the header).

Metric definitions (also emitted into the written doc):
  valid_json   — SLM responses from which extract_json recovered an object
                 carrying both "pattern" and "field_mappings" / all responses.
  compiles     — of those, patterns that re.compile() (the __JSON__ sentinel
                 counts as compiling).
  held_out     — mean validate_candidate held_out_match_rate over the runs
                 that produced a rule (a run whose retries were exhausted
                 contributes no rate and is counted in failures).
  attempts     — mean chat() calls per run (1.0 = first response usable).
  s/rule       — total run wall-clock (generation + validation, failed runs
                 included) divided by rules stored.

Stdlib + onboarding imports only at module load; `ollama` stays lazy inside
OllamaClient.chat, so this imports (and the unit tests run) without it. No
DB, no pytest against the live endpoint — a manual bench tool.

Run from the repo root:
  python bench/onboarding_eval/sanity_eval.py --runs 3 \
      --model qwen3:4b --url http://ollama-4b:11434 --write docs/m2-slm-sanity.md
"""
from __future__ import annotations

import argparse
import json
import platform
import re
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
# The onboarding package lives under services/ (pytest does the same insertion
# for the unit tests; the bench script must also work standalone).
sys.path.insert(0, str(REPO_ROOT / "services"))

from onboarding.generate import GenerationError, extract_json, generate_candidate
from onboarding.samples import assign_roles
from ulpf_core.parsing import JSON_SENTINEL
from ulpf_core.validation import validate_candidate

CORPUS_NAMES = ("acmegw", "zenwall", "newapp")
HEADERS = ["corpus", "runs", "rules", "valid_json", "compiles",
           "held_out_match", "mean_attempts", "s/rule"]


# ---------- formatting (pure; unit-tested) ----------

def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def num(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1f}"


def format_table(headers: list[str], rows: list[list[str]]) -> str:
    """Markdown table with columns padded to the widest cell per column."""
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def line(cells: list[str]) -> str:
        return "| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells)) + " |"

    out = [line(headers), "| " + " | ".join("-" * w for w in widths) + " |"]
    out.extend(line(row) for row in rows)
    return "\n".join(out)


# ---------- corpus resolution ----------

def find_corpora(names: list[str], dirs: list[Path]) -> dict[str, Path | None]:
    """First raw_logs_<name>.txt found across `dirs` (in order); None if a
    corpus is missing everywhere — reported, not fatal."""
    found: dict[str, Path | None] = {}
    for name in names:
        path = next((d / f"raw_logs_{name}.txt" for d in dirs
                     if (d / f"raw_logs_{name}.txt").is_file()), None)
        found[name] = path
    return found


def load_lines(path: Path) -> list[str]:
    return [line for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


# ---------- the harness ----------

class RecordingClient:
    """Wraps an SLMClient; records every response + its chat latency so the
    tally sees per-attempt truth (generate_candidate only surfaces the rule)."""

    def __init__(self, inner):
        self.inner = inner
        self.calls: list[tuple[str, float]] = []

    def chat(self, prompt: str, temperature: float) -> str:
        start = time.monotonic()
        text = self.inner.chat(prompt, temperature)
        self.calls.append((text, time.monotonic() - start))
        return text


class ChatTimeout(Exception):
    """A single chat() call exceeded the --chat-timeout bound. Rides the
    production retry ladder like any transport failure, so a degenerate
    answer becomes honest failed-run rows instead of an overnight hang."""


class TimeoutClient:
    """Opt-in per-chat wall-clock bound (the "no overnight failure loops"
    mechanism). Runs the inner chat on a daemon thread: on expiry the eval
    proceeds immediately and the abandoned call can never block interpreter
    exit. Default (no bound) stays production-faithful."""

    def __init__(self, inner, timeout_s: float):
        self.inner = inner
        self.timeout_s = timeout_s

    def chat(self, prompt: str, temperature: float) -> str:
        outcome: dict = {}

        def run():
            try:
                outcome["text"] = self.inner.chat(prompt, temperature)
            except Exception as exc:  # noqa: BLE001 - relayed verbatim below
                outcome["exc"] = exc

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(self.timeout_s)
        if worker.is_alive():
            raise ChatTimeout(f"no response within {self.timeout_s:.0f}s")
        if "exc" in outcome:
            raise outcome["exc"]
        return outcome["text"]


def _response_shape_ok(text: str) -> bool:
    """valid_json metric: extract_json recovered an object with the two
    required keys (deeper breakage — bad mapping shapes — counts as valid
    JSON but is caught downstream by generate_candidate's retries)."""
    try:
        parsed = extract_json(text)
    except (ValueError, json.JSONDecodeError):
        return False
    return isinstance(parsed, dict) and "pattern" in parsed and "field_mappings" in parsed


def _pattern_compiles(pattern: str) -> bool:
    if pattern == JSON_SENTINEL:
        return True
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def evaluate_corpus(corpus: str, lines: list[str], *, client_factory,
                    runs: int, prompt_size: int = 5, held_out_size: int = 15) -> dict:
    """One corpus through the production path, `runs` times (fresh SLM calls
    each run; the deterministic split is derived once)."""
    rows = [{"id": i, "raw_text": line} for i, line in enumerate(lines)]
    split = assign_roles(rows, prompt_size, held_out_size)
    prompt_lines = [row["raw_text"] for row in split["prompt"]]
    held_out_lines = [row["raw_text"] for row in split["held_out"]]

    responses = valid_json = compiles = 0
    rules_stored = 0
    attempt_counts: list[int] = []
    match_rates: list[float] = []
    wall = 0.0
    failures: list[str] = []

    for _ in range(runs):
        client = RecordingClient(client_factory())
        start = time.monotonic()
        try:
            rule = generate_candidate("sanity-eval", prompt_lines, client)
        except GenerationError as exc:
            wall += time.monotonic() - start
            failures.append(f"{len(client.calls)} attempts: {exc}")
        else:
            wall += time.monotonic() - start
            report = validate_candidate(rule, prompt_lines, held_out_lines)
            rules_stored += 1
            match_rates.append(report.held_out_match_rate)

        attempt_counts.append(len(client.calls))
        for text, _ in client.calls:
            responses += 1
            if _response_shape_ok(text):
                valid_json += 1
                if _pattern_compiles(extract_json(text)["pattern"]):
                    compiles += 1

    return {
        "corpus": corpus,
        "runs": runs,
        "rules_stored": rules_stored,
        "responses": responses,
        "valid_json": valid_json,
        "compiles": compiles,
        "held_out_match_rate": (sum(match_rates) / len(match_rates)
                                if match_rates else None),
        "mean_attempts": (sum(attempt_counts) / len(attempt_counts)
                          if attempt_counts else None),
        "sec_per_rule": wall / rules_stored if rules_stored else None,
        "prompt_n": len(prompt_lines),
        "held_out_n": len(held_out_lines),
        "failures": failures,
    }


def _row(result: dict) -> list[str]:
    responses = result["responses"] or None
    return [
        result["corpus"],
        str(result["runs"]),
        str(result["rules_stored"]),
        pct(result["valid_json"] / responses if responses else None),
        pct(result["compiles"] / responses if responses else None),
        pct(result["held_out_match_rate"]),
        num(result["mean_attempts"]),
        num(result["sec_per_rule"]),
    ]


def build_doc(results: list[dict], *, model: str, host_cpu: str,
              date_str: str, runs: int, chat_timeout: float | None = None) -> str:
    """docs/m2-slm-sanity.md body: measured header notes, metric definitions,
    the numbers table, and per-corpus failure footnotes (only when a run's
    retries were exhausted)."""
    lines = [
        "# M2 SLM sanity numbers — onboarding candidate loop",
        "",
        "Measured numbers only (bench/onboarding_eval/sanity_eval.py against a",
        "live Ollama endpoint; the split + generation + validation are the",
        "production code paths).",
        "",
        f"- model: {model}",
        f"- host CPU: {host_cpu}",
        f"- date: {date_str}",
        f"- runs per corpus: {runs}",
    ]
    if chat_timeout is not None:
        lines.append(
            f"- per-chat timeout: {int(chat_timeout)}s (eval-side bound; the "
            "production loop is unbounded)")
    lines += [
        "",
        "Metric definitions: `valid_json` = SLM responses from which",
        "`extract_json` recovered an object with `pattern` + `field_mappings`;",
        "`compiles` = of those, patterns that compile (`__JSON__` sentinel counts);",
        "`held_out_match` = mean `validate_candidate` held-out match rate over runs",
        "that produced a rule; `mean_attempts` = mean chat() calls per run;",
        "`s/rule` = run wall-clock per stored rule (failed runs included in the",
        "numerator). Split: 5 prompt / up to 15 held-out per corpus.",
        "",
        format_table(HEADERS, [_row(r) for r in results]),
    ]
    for result in results:
        if result.get("failures"):
            lines += ["", f"{result['corpus']} failures:"]
            lines += [f"- {failure}" for failure in result["failures"]]
    lines.append("")
    return "\n".join(lines)


# ---------- CLI ----------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sanity_eval.py",
        description="Offline SLM sanity numbers for the onboarding candidate loop.")
    parser.add_argument("--corpora", action="append", default=None, metavar="DIR",
                        help="directory holding raw_logs_*.txt (repeatable; default: "
                             "the repo's golden + simulator/data locations)")
    parser.add_argument("--runs", type=int, default=3,
                        help="generation runs per corpus (default 3)")
    parser.add_argument("--model", default="qwen3:4b",
                        help="SLM tag (default qwen3:4b)")
    parser.add_argument("--url", default="http://localhost:11434",
                        help="Ollama base URL (default http://localhost:11434; the "
                             "compose sidecar is http://ollama-4b:11434 from the "
                             "compose network)")
    parser.add_argument("--write", default=None, metavar="PATH",
                        help="also write the full markdown doc (e.g. docs/m2-slm-sanity.md)")
    parser.add_argument("--host-cpu", default=None, dest="host_cpu",
                        help="host CPU description for the doc header "
                             "(default: platform.processor())")
    parser.add_argument("--chat-timeout", type=float, default=None,
                        dest="chat_timeout", metavar="SECONDS",
                        help="bound each chat() call (eval-side; the production "
                             "loop is unbounded). A timed-out call retries like "
                             "any transport failure, so a degenerate answer "
                             "becomes honest failed-run rows instead of an "
                             "overnight hang.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    dirs = ([Path(d) for d in args.corpora] if args.corpora else
            [REPO_ROOT / "libs/ulpf-core/tests/data/golden", REPO_ROOT / "simulator/data"])
    found = find_corpora(list(CORPUS_NAMES), dirs)

    missing = [name for name, path in found.items() if path is None]
    for name in missing:
        print(f"warning: raw_logs_{name}.txt not found in "
              f"{[str(d) for d in dirs]}; skipping", file=sys.stderr)
    if not missing:
        print(f"corpora: {', '.join(f'{n}={found[n]}' for n in CORPUS_NAMES)}",
              file=sys.stderr)

    from onboarding.generate import OllamaClient  # deferred: SLM tier only

    def client_factory():
        client = OllamaClient(args.url, args.model)
        if args.chat_timeout is not None:
            client = TimeoutClient(client, args.chat_timeout)
        return client

    results = []
    for name in CORPUS_NAMES:
        if found[name] is None:
            continue
        print(f"evaluating {name} ({found[name]}) ...", file=sys.stderr)
        results.append(evaluate_corpus(name, load_lines(found[name]),
                                       client_factory=client_factory, runs=args.runs))
    if not results:
        print("error: no corpora evaluated", file=sys.stderr)
        return 2

    table = format_table(HEADERS, [_row(r) for r in results])
    print(table)

    if args.write:
        doc = build_doc(results, model=args.model,
                        host_cpu=args.host_cpu or platform.processor() or "unknown",
                        date_str=datetime.now().astimezone().date().isoformat(),
                        runs=args.runs, chat_timeout=args.chat_timeout)
        out = Path(args.write)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(doc, encoding="utf-8")
        print(f"wrote {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
