"""Deterministic candidate validation gate (spec §6.2 step 4, §6.3).

Shared by the onboarding service (SLM candidates) and the gateway (manual
authoring + approve-with-edits revalidation). Everything here is pure: rules
and lines in, CandidateReport out; no DB, no model calls.
"""
import random
import re
from dataclasses import dataclass, field

import regex

# Probe mutation ops (IPv4/port/timestamp/hostname/digit-run, values-only).
# Single definition ported from bench/fingerprint_fragmentation.py lives in
# ulpf_core.mutations; re-exported here as the M2 interface name (Tasks 5/7
# import ulpf_core.validation.mutate_line). Bench passes vary_text=True there.
from ulpf_core.mutations import mutate_line
from ulpf_core.parsing import JSON_SENTINEL, parse, validate_rule_output

CHECK_KEYS = ("caps_and_allowlist", "samples_parse", "held_out_match_all",
              "ip_fields_valid", "port_fields_valid", "no_orphan_mappings",
              "adversarial_probe", "no_hardcoded_literals")

# Adversarial probe: value mutants per prompt line, all from one fixed seed so
# validate_candidate is deterministic (tests must be stable across runs).
PROBE_MUTANTS_PER_LINE = 20
PROBE_SEED = 20260919
PREVIEW_CAP = 5


@dataclass(frozen=True)
class CandidateReport:
    passed: bool
    checks: dict[str, bool]
    held_out_match_rate: float
    notes: list[str] = field(default_factory=list)
    previews: list[dict] = field(default_factory=list)
    # Line counts so report_to_json can emit truthful prompt_count /
    # held_out_count; trailing defaults keep the five-field contract above.
    prompt_count: int = 0
    held_out_count: int = 0


# Mapped-value sanity shapes (checked AFTER parse).
_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
# Literal-extraction scans for the hardcoding check: timestamps, IPs,
# hostnames, then >=3-digit numbers outside already-claimed spans.
_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ][0-9:.]+Z?")
_IP_SCAN_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_HOSTNAME_SCAN_RE = re.compile(r"\b[a-z][a-z0-9-]*\d{1,4}\b")  # fw01, vpn-gw01, eth0
_NUM_SCAN_RE = re.compile(r"\d{3,}")


def validate_candidate(rule, prompt_lines, held_out_lines):
    """All CHECK_KEYS True == candidate may be stored for review. With no
    samples, sample-dependent checks are skipped-and-noted (check key stays
    True, a 'no samples' note is added) — manual authoring for an unseen
    format must not be blocked for lack of samples."""
    samples = prompt_lines + held_out_lines
    # 1. caps/compile/allow-list/output-schema via the M1 gate
    base = validate_rule_output(rule, samples) if samples else []
    checks = {"caps_and_allowlist": not base}
    notes = list(base)
    if not samples:
        notes.append("no samples provided; sample-dependent checks (parse, value "
                     "sanity, orphan, probe, hardcoding) were skipped")

    # 2. per-line parse + value sanity (prompt + held-out for sanity; match-rate
    #    counted on held-out ONLY)
    docs: list[dict] = []
    samples_parse = ip_fields_valid = port_fields_valid = True
    held_out_matched = 0
    previews: list[dict] = []
    for role, lines in (("prompt", prompt_lines), ("held-out", held_out_lines)):
        for i, line in enumerate(lines):
            doc, err = parse(line, rule)
            if err is not None:
                samples_parse = False
                notes.append(f"{role} line {i}: {err}")
                if role == "held-out" and len(previews) < PREVIEW_CAP:
                    previews.append({"line": line, "status": "error", "ocsf": None})
                continue
            docs.append(doc)
            if role == "held-out":
                held_out_matched += 1
                if len(previews) < PREVIEW_CAP:
                    previews.append({"line": line, "status": "parsed", "ocsf": doc})
            for key, note in _value_sanity(doc, role, i):
                notes.append(note)
                if key == "ip_fields_valid":
                    ip_fields_valid = False
                elif key == "port_fields_valid":
                    port_fields_valid = False
                else:
                    samples_parse = False
    checks["samples_parse"] = samples_parse
    checks["held_out_match_all"] = held_out_matched == len(held_out_lines)
    checks["ip_fields_valid"] = ip_fields_valid
    checks["port_fields_valid"] = port_fields_valid

    # 3. orphans across all produced fields (sample-dependent: with no samples
    #    nothing can be observed, so skip-and-keep-True like the rest)
    if samples:
        seen = _observed_fields(rule, docs)
        orphans = [m.source_field for m in rule.mappings if m.source_field not in seen]
        checks["no_orphan_mappings"] = not orphans
        if orphans:
            notes.append(f"orphan mappings (source field never observed): {orphans}")
    else:
        checks["no_orphan_mappings"] = True

    # 4. adversarial probe: N mutants per prompt line must still parse
    probe_ok = True
    if prompt_lines:
        rng = random.Random(PROBE_SEED)
        for i, line in enumerate(prompt_lines):
            for _ in range(PROBE_MUTANTS_PER_LINE):
                doc, err = parse(mutate_line(line, rng), rule)
                if err is not None:
                    probe_ok = False
                    notes.append(
                        f"adversarial probe: prompt line {i} mutant failed to parse: {err}"
                    )
                    break
    checks["adversarial_probe"] = probe_ok

    # 5. hardcoding: literals that vary across prompt lines must not appear
    #    verbatim in the pattern
    offending = find_hardcoded_literals(rule.pattern, prompt_lines)
    checks["no_hardcoded_literals"] = not offending
    if offending:
        notes.append(f"hardcoded literals (vary across prompt lines): {offending}")

    rate = held_out_matched / len(held_out_lines) if held_out_lines else 1.0
    return CandidateReport(passed=all(checks.values()), checks=checks,
                           held_out_match_rate=rate, notes=notes, previews=previews,
                           prompt_count=len(prompt_lines), held_out_count=len(held_out_lines))


def report_to_json(report):
    """The rules.validation JSONB shape (exact key set; Tasks 5/7 store and
    serve this verbatim)."""
    return {
        "passed": report.passed,
        "checks": dict(report.checks),
        "held_out_match_rate": report.held_out_match_rate,
        "notes": list(report.notes),
        "previews": [dict(p) for p in report.previews],
        "prompt_count": report.prompt_count,
        "held_out_count": report.held_out_count,
    }


def find_hardcoded_literals(pattern, prompt_lines):
    """Literals that DISTINGUISH one prompt line from another (timestamps,
    IPs, hostnames, >=3-digit numbers) yet appear verbatim in `pattern`.
    Token-diff approach: extract candidate literals per line with the scan
    regexes; a literal present in the pattern AND not common to every line is
    hardcoded. With fewer than two prompt lines nothing is provably common —
    a single sample gives no evidence of variation, so any of its literals
    baked into the pattern counts. Returns the sorted offending literals."""
    per_line = [_extract_literals(line) for line in prompt_lines]
    common = set.intersection(*per_line) if len(per_line) >= 2 else set()
    return sorted({lit for lits in per_line for lit in lits
                   if lit not in common and lit in pattern})


def _extract_literals(line: str) -> set[str]:
    """Timestamps, IPs and hostnames, plus >=3-digit runs that are not part
    of one of those (a 100 inside an IP is not a standalone literal)."""
    lits: set[str] = set()
    claimed: list[tuple[int, int]] = []
    for rx in (_TS_RE, _IP_SCAN_RE, _HOSTNAME_SCAN_RE):
        for m in rx.finditer(line):
            lits.add(m.group())
            claimed.append(m.span())
    for m in _NUM_SCAN_RE.finditer(line):
        if any(max(s, m.start()) < min(e, m.end()) for s, e in claimed):
            continue
        lits.add(m.group())
    return lits


def _value_sanity(doc: dict, role: str, i: int):
    """Yield (CHECK_KEY, note) per mapped value failing sanity. IP values
    must match _IP_RE, ports must be ints in 0-65535 (a port that survived
    _as_int as a string is a failure), severity_id an int in 0-6 or None."""
    for path in ("src_endpoint.ip", "dst_endpoint.ip"):
        v = _doc_get(doc, path)
        if v is not None and not (isinstance(v, str) and _IP_RE.match(v)):
            yield "ip_fields_valid", f"{role} line {i}: {path} value {v!r} is not an IPv4 address"
    for path in ("src_endpoint.port", "dst_endpoint.port"):
        v = _doc_get(doc, path)
        if v is not None and not _is_int_in(v, 0, 65535):
            yield ("port_fields_valid",
                   f"{role} line {i}: {path} value {v!r} is not a port in 0-65535")
    sev = doc.get("severity_id")
    if sev is not None and not _is_int_in(sev, 0, 6):
        yield "samples_parse", f"{role} line {i}: severity_id {sev!r} is not an int in 0-6"


def _is_int_in(v, lo: int, hi: int) -> bool:
    # bool is an int subclass — True/False are neither ports nor severities.
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _doc_get(doc: dict, dotted_path: str):
    """Walk a document by dotted OCSF path ('src_endpoint.ip')."""
    current = doc
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _observed_fields(rule, docs) -> set[str]:
    """Every source-field name the samples actually produced: named groups of
    the pattern, keys seen in parsed docs' `unmapped`, and mapped source
    fields (they left a non-None value at their OCSF target — a mapped
    extension-blob key never shows up in `unmapped`). Ports the
    fields_seen_anywhere logic of legacy-demo/ingestion/validate_rule.py,
    adapted to parse() outputs."""
    seen: set[str] = set()
    if rule.pattern != JSON_SENTINEL:
        try:
            seen |= set(regex.compile(rule.pattern).groupindex)
        except regex.error:
            pass  # broken patterns are already reported by caps_and_allowlist
    for doc in docs:
        seen |= set((doc.get("unmapped") or {}).keys())
    resolved = {m.ocsf_path for m in rule.mappings
                if any(_doc_get(d, m.ocsf_path) is not None for d in docs)}
    seen |= {m.source_field for m in rule.mappings if m.ocsf_path in resolved}
    return seen
