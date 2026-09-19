#!/usr/bin/env python3
"""Fragmentation bench for ulpf-core fingerprinting (spec §9, M1).

For every golden corpus (libs/ulpf-core/tests/data/golden/raw_logs_*.txt):

1. Fingerprint every line and group by ``fingerprint_id``. A known-format
   group whose lines do not all share one shape hash is a fragmentation.
2. Generate 100 mutated lines per corpus. Mutations randomize timestamps,
   IPs, ports (``IP:port``, ``key=value`` and JSON numeric fields), hostnames
   (``h####``) and free-text message word counts — exactly the values that
   vary between real events of the same format.
3. A mutant is stable iff it keeps its base line's fingerprint (known formats)
   and its base line's shape hash. Report per-corpus distinct shape hashes
   and the mutation-stability ratio.

Exit status: 0 if every known-format group is fragmentation-free and fully
mutation-stable, 1 otherwise. (``auto_`` groups cannot fragment by
construction: the provisional id is derived from the shape hash itself.)

Run from the repo root:  python bench/fingerprint_fragmentation.py
Writes: docs/m1-fragmentation.md
"""

from __future__ import annotations

import random
import re
import sys
from collections.abc import Callable
from pathlib import Path

from ulpf_core.fingerprint import _classify, fingerprint_id, shape_hash

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "libs" / "ulpf-core" / "tests" / "data" / "golden"
DOC = ROOT / "docs" / "m1-fragmentation.md"

SEED = 20260919
MUTATIONS = 100

# --- mutation machinery ------------------------------------------------------
# Timestamps mutate first and park behind \x00 sentinels so later numeric
# passes cannot chew freshly generated values into shape-breaking forms.
# IP:port mutates before the IP pass so the ":port" tail does not lose the
# digit its lookbehind needs.

_ISO_TS_RE = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}):(\d{2}))?([+-]\d{2}:?\d{2}|Z)?"
)
_SYSLOG_TS_RE = re.compile(
    r"\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec))\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\b"
)
_PORT_RE = re.compile(r"(?<=\d):\d{1,5}\b")              # port tail of IP:port
_IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_KV_NUM_RE = re.compile(r"(?<==)\d{1,5}\b")               # key=12345 values
_JSON_NUM_RE = re.compile(r'(?<=":)\d{1,5}\b')            # "key":12345 values
_HOSTNAME_RE = re.compile(r"\b[a-z][a-z0-9-]*\d{1,4}\b")  # fw01, vpn-gw01, eth0
_SENTINEL_RE = re.compile(r"\x00A(\d+)\x00")
_MONTH_RE = re.compile(r"^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$")
_MARKUP_CHARS = set('{}"<>')


def _rand_iso_ts(match: re.Match[str], rng: random.Random) -> str:
    text = f"{rng.randint(2020, 2030):04d}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"
    if match.group(4):
        text += f"T{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}"
    return text + (match.group(7) or "")


def _rand_syslog_ts(match: re.Match[str], rng: random.Random) -> str:
    # Keep the month word so the mutant still detects as syslog.
    return (
        f"{match.group(1)} {rng.randint(1, 28)} "
        f"{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}"
    )


def _rand_ip(rng: random.Random) -> str:
    return ".".join(str(rng.randint(1, 254)) for _ in range(4))


def mutate_line(line: str, rng: random.Random) -> str:
    """Return a same-format mutant of *line* with randomized values."""
    stash: list[str] = []

    def _swap(make: Callable[[re.Match[str]], str]) -> Callable[[re.Match[str]], str]:
        def _sub(match: re.Match[str]) -> str:
            stash.append(make(match))
            return f"\x00A{len(stash) - 1}\x00"

        return _sub

    line = _ISO_TS_RE.sub(_swap(lambda m: _rand_iso_ts(m, rng)), line)
    line = _SYSLOG_TS_RE.sub(_swap(lambda m: _rand_syslog_ts(m, rng)), line)
    line = _PORT_RE.sub(_swap(lambda m: f":{rng.randint(1, 65535)}"), line)
    line = _IP_RE.sub(_swap(lambda m: _rand_ip(rng)), line)
    line = _KV_NUM_RE.sub(_swap(lambda m: str(rng.randint(1, 65535))), line)
    line = _JSON_NUM_RE.sub(_swap(lambda m: str(rng.randint(1, 65535))), line)
    line = _HOSTNAME_RE.sub(_swap(lambda m: f"h{rng.randint(0, 9999):04d}"), line)

    # Free-text runs (message bodies) get a random word count. Structural
    # tokens (markup, sentinels, syslog month, anything classified) are kept.
    if " " in line:
        kept: list[str] = []
        run: list[str] = []

        def _flush() -> None:
            if run:
                kept.extend(rng.choice(WORDS) for _ in range(rng.randint(1, 6)))
                run.clear()

        for token in line.split():
            if (
                _SENTINEL_RE.fullmatch(token)
                or _MONTH_RE.fullmatch(token)
                or _MARKUP_CHARS.intersection(token)
                or _classify(token) != "W"
            ):
                _flush()
                kept.append(token)
            else:
                run.append(token)
        _flush()
        line = " ".join(kept)

    return _SENTINEL_RE.sub(lambda m: stash[int(m.group(1))], line)


WORDS = [
    "alpha", "bravo", "delta", "echo", "fox", "golf",
    "hotel", "india", "juliet", "kilo", "lima", "mike",
]


def run_bench(mutations: int = MUTATIONS, seed: int = SEED) -> dict:
    rng = random.Random(seed)
    corpora = sorted(GOLDEN.glob("raw_logs_*.txt"))
    if not corpora:
        raise SystemExit(f"no golden corpora found under {GOLDEN}")

    report: dict = {"seed": seed, "mutations": mutations, "corpora": [], "passed": True}
    for path in corpora:
        lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        groups: dict[str, list[str]] = {}
        for line in lines:
            groups.setdefault(fingerprint_id(line), []).append(line)

        group_rows = []
        for fp in sorted(groups):
            hashes = {shape_hash(l) for l in groups[fp]}
            known = not fp.startswith("auto_")
            fragmented = known and len(hashes) > 1
            group_rows.append({
                "fingerprint": fp,
                "lines": len(groups[fp]),
                "distinct_hashes": len(hashes),
                "fragmented": fragmented,
            })

        canonical = {fp: shape_hash(ls[0]) for fp, ls in groups.items()}
        mutant_hashes: set[str] = set()
        stable = 0
        failures: list[str] = []
        for _ in range(mutations):
            base = rng.choice(lines)
            fp = fingerprint_id(base)
            mutant = mutate_line(base, rng)
            mutant_hashes.add(shape_hash(mutant))
            ok = shape_hash(mutant) == canonical[fp]
            if not fp.startswith("auto_"):
                ok = ok and fingerprint_id(mutant) == fp
            if ok:
                stable += 1
            elif not fp.startswith("auto_"):
                failures.append(
                    f"[{path.name}] {fp} mutant unstable:\n"
                    f"    base:   {base}\n    mutant: {mutant}"
                )

        known_failure = any(r["fragmented"] for r in group_rows) or bool(failures)
        report["passed"] &= not known_failure
        report["corpora"].append({
            "name": path.name,
            "lines": len(lines),
            "groups": group_rows,
            "group_count": len(groups),
            "distinct_line_hashes": len({shape_hash(l) for l in lines}),
            "distinct_mutant_hashes": len(mutant_hashes),
            "stability": stable / mutations,
            "failed": known_failure,
            "failures": failures,
        })
    return report


def write_doc(report: dict) -> None:
    out: list[str] = [
        "# M1 fragmentation bench (spec §9)",
        "",
        (
            f"Generated by `python bench/fingerprint_fragmentation.py` "
            f"(seed {report['seed']}, {report['mutations']} mutants per corpus). "
            "Do not edit by hand; re-run to regenerate."
        ),
        "",
        "## Method",
        "",
        "- Golden corpora live in `libs/ulpf-core/tests/data/golden/raw_logs_*.txt`.",
        "- Lines are grouped by `fingerprint_id`; every line in a group must share",
        "  one shape hash (the CEF corpus intentionally holds 3 vendor groups).",
        "- Each corpus also gets 100 mutants with randomized timestamps, IPs, ports,",
        "  hostnames (`h####`) and message word counts. A mutant is stable iff it",
        "  keeps its base line's fingerprint (known formats) and shape hash.",
        "- Exit is non-zero if any known-format group fragments or loses a mutant",
        "  (`auto_` groups cannot fragment by construction: id = shape hash).",
        "",
        "## Results",
        "",
        "| corpus | lines | fingerprint groups | distinct line shape hashes | distinct mutant shape hashes | mutation stability | result |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for corpus in report["corpora"]:
        out.append(
            f"| {corpus['name']} | {corpus['lines']} | {corpus['group_count']} "
            f"| {corpus['distinct_line_hashes']} | {corpus['distinct_mutant_hashes']} "
            f"| {corpus['stability']:.0%} | {'FAIL' if corpus['failed'] else 'PASS'} |"
        )
    out += ["", "## Per fingerprint group", "",
            "| corpus | fingerprint_id | lines | distinct shape hashes | result |",
            "|---|---|---:|---:|---|"]
    for corpus in report["corpora"]:
        for row in corpus["groups"]:
            out.append(
                f"| {corpus['name']} | `{row['fingerprint']}` | {row['lines']} "
                f"| {row['distinct_hashes']} | {'FAIL' if row['fragmented'] else 'PASS'} |"
            )
    out += [
        "",
        "## Reading the numbers",
        "",
        "- `distinct line shape hashes == fingerprint groups` means the golden lines",
        "  do not fragment within any format.",
        "- `mutation stability 100%` means no realistic value mutation changes a",
        "  line's shape — the property drift detection (later milestones) relies on.",
        "",
    ]
    DOC.write_text("\n".join(out), encoding="utf-8")


def main() -> int:
    report = run_bench()
    write_doc(report)

    print(f"seed={report['seed']} mutants/corpus={report['mutations']}")
    for corpus in report["corpora"]:
        status = "FAIL" if corpus["failed"] else "PASS"
        print(
            f"{corpus['name']:<28} lines={corpus['lines']:<3} "
            f"groups={corpus['group_count']} "
            f"line_hashes={corpus['distinct_line_hashes']} "
            f"mutant_hashes={corpus['distinct_mutant_hashes']} "
            f"stability={corpus['stability']:.0%} {status}"
        )
        for failure in corpus["failures"]:
            print(failure)
    print(f"wrote {DOC.relative_to(ROOT)}")
    print("RESULT:", "PASS" if report["passed"] else "FAIL")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
