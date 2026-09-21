# services/drift/enforce.py — graduated, fail-closed enforcement (R-M3-11,
# spec §7.2) under drift_role's column-scoped grants (migration 007).
#
# The grant surface IS the design, exactly as in gateway/writes.py: drift_role
# may UPDATE ONLY rules(quarantined_fields) and rules(status, deactivated_at),
# INSERT drift_windows/baseline_profiles/audit_log, and SELECT its own tables.
# Every UPDATE carries its expected-state predicate in the WHERE (TOCTOU
# backstop) and is answered by a rowcount check — 0 rows means another writer
# moved the rule (already quarantined / no longer active): False, never a
# silent no-op that would still write an audit row. On a successful mutation
# the audit INSERT is paired INSIDE the same transaction, actor 'drift'
# (store.ACTOR).
#
# Worst-first scan enforcement (enforce_findings): severe findings before
# moderate; ONE deactivate per fingerprint per scan; after a deactivate the
# remaining actions for that fingerprint are skipped and logged (the rule is
# down — quarantine appends would no-op against status='active' anyway).
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ulpf_core.drift import SEVERITIES

from drift.detect import Finding, merge_findings, window_rows
from drift.store import ACTOR, insert_windows

if TYPE_CHECKING:
    import psycopg

    from drift.store import ActiveDriftRule
    from drift.windows import Window

log = logging.getLogger("drift.enforce")

_AUDIT_SQL = "INSERT INTO audit_log (actor, action, entity, detail) VALUES (%s, %s, %s, %s)"

# Column-scoped exactly to migration 007's grants; the NOT (... = ANY(...))
# term is the idempotency predicate — quarantining an already-quarantined
# field matches zero rows and cannot audit.
_QUARANTINE_SQL = (
    "UPDATE rules SET quarantined_fields = array_append(quarantined_fields, %s) "
    "WHERE id = %s AND status = 'active' "
    "AND NOT (%s = ANY(quarantined_fields))"
)
_DEACTIVATE_SQL = (
    "UPDATE rules SET status = 'deactivated', deactivated_at = now() "
    "WHERE id = %s AND status = 'active'"
)


def _audit(cur, action: str, entity: str, detail: dict) -> None:
    from psycopg.types.json import Json  # deferred: keeps psycopg off the test path

    cur.execute(_AUDIT_SQL, (ACTOR, action, entity, Json(detail)))


def quarantine_field(conn: psycopg.Connection, rule: ActiveDriftRule, field: str,
                     window_start) -> bool:
    """Append one field to the rule's quarantined_fields (mapping disabled at
    parse time; values preserved in unmapped). Idempotent: the NOT (... = ANY
    (...)) predicate means an already-quarantined field — or a rule that is no
    longer active — updates zero rows, returns False and writes NO audit (a
    no-op must never look like an action). True iff the append happened, in
    which case the audit row is paired in the same transaction."""
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(_QUARANTINE_SQL, (field, rule.id, field))
        if cur.rowcount == 0:
            log.info("quarantine no-op for %s v%d field %s (already quarantined "
                     "or rule inactive)", rule.fingerprint_id, rule.version, field)
            return False
        _audit(cur, "field_quarantined", rule.fingerprint_id,
               {"field": field, "rule_id": rule.id, "version": rule.version,
                "window_start": window_start})
    log.warning("field %s quarantined on %s v%d (window %s)",
                field, rule.fingerprint_id, rule.version, window_start)
    return True


def deactivate_rule(conn: psycopg.Connection, rule: ActiveDriftRule,
                    window_start) -> bool:
    """Deactivate the rule (fingerprint reverts to raw-only and re-enters
    onboarding). The status='active' predicate is the expected-state TOCTOU
    backstop: zero rows -> False (a human or another scan got there first),
    never an audit for something that did not happen."""
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(_DEACTIVATE_SQL, (rule.id,))
        if cur.rowcount == 0:
            log.info("deactivate no-op for rule %d (no longer active)", rule.id)
            return False
        _audit(cur, "rule_deactivated", rule.fingerprint_id,
               {"rule_id": rule.id, "version": rule.version,
                "window_start": window_start})
    log.warning("rule %d (%s v%d) DEACTIVATED by drift (window %s)",
                rule.id, rule.fingerprint_id, rule.version, window_start)
    return True


def record_windows(conn: psycopg.Connection, rule: ActiveDriftRule,
                   findings: list[Finding], win: Window) -> None:
    """INSERT one window's drift_windows rows with the DECIDED severity and
    action_taken overlaid onto the measured row (window_rows recomputes the
    rates — the exact tier-1 measurement discipline — and the finding supplies
    the decision). Idempotent by the deterministic window key through
    store.insert_windows' ON CONFLICT DO NOTHING; one transaction per window
    batch. The plan's listed form record_windows(conn, findings, win) lacked
    the rule identity the INSERT columns need — rule leads, mirroring
    window_rows(rule, windows)."""
    by_field = {finding.field: finding for finding in findings}
    rows = []
    for measured in window_rows(rule, [win]):
        finding = by_field.get(measured[2])
        if finding is None:  # defensive: emission parity is pinned by test
            rows.append(measured)
        else:
            rows.append(measured[:10] + (finding.severity, finding.action))
    insert_windows(conn, rows)


def _rank(severity: str) -> int:
    return SEVERITIES.index(severity)


def enforce_findings(conn: psycopg.Connection, rule: ActiveDriftRule,
                     findings: list[Finding]) -> dict:
    """Enforce one scan's findings, worst-first (R-M3-11): severe before
    moderate (alerts need no enforcement — the drift_windows row IS the
    alert), ONE deactivate per fingerprint per scan, and after a deactivate
    the remaining actions for this fingerprint are skipped and logged.
    Returns {"deactivated": bool, "quarantined": [fields actually appended]}.
    """
    merged = merge_findings(findings)  # per-field max severity (R-M3-11)
    worst: dict[str, Finding] = {}     # that max, as the finding that carries it
    # (enforcement needs the finding's window_start for the audit detail)
    for finding in sorted(findings,
                          key=lambda f: (-_rank(f.severity), f.window_start, f.field)):
        if merged.get(finding.field, "none") == finding.severity:
            worst.setdefault(finding.field, finding)

    quarantined: list[str] = []
    deactivated = False
    skip_rest = False
    for finding in sorted(worst.values(), key=lambda f: (-_rank(f.severity), f.field)):
        if skip_rest:
            log.info("skipping %s on %s (window %s): the rule was deactivated "
                     "this scan", finding.action, finding.field, finding.window_start)
            continue
        if finding.action == "alert":
            # minor (or sentinel-moderate): alert + metric logged — no DB action.
            log.warning("drift alert: %s v%d field %s severity %s (window %s) "
                        "stats %s", rule.fingerprint_id, rule.version, finding.field,
                        finding.severity, finding.window_start, finding.stats)
        elif finding.action == "rule_deactivated":
            skip_rest = True  # one deactivate per fingerprint per scan
            deactivated = deactivate_rule(conn, rule, finding.window_start)
            if not deactivated:
                log.info("rule %d no longer active; drift enforcement stands "
                         "down for this scan", rule.id)
        elif (finding.action == "field_quarantined"
              and quarantine_field(conn, rule, finding.field, finding.window_start)):
            quarantined.append(finding.field)
    return {"deactivated": deactivated, "quarantined": quarantined}
