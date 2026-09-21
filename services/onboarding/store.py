# services/onboarding/store.py — all onboarding DB access (cold path).
#
# Every function takes a live connection (one conn per call: the app loop
# opens and closes a connection around each step) and imports psycopg lazily,
# so unit tests drive everything through fake conns — never a live DB.
# Connections run AUTOCOMMIT (the T7 house style): each multi-statement
# operation wraps exactly one `with conn.transaction():` block, single
# statements rely on autocommit.
#
# Grant shape (migration 003): onboarding_role has SELECT+INSERT on rules,
# INSERT on audit_log, SELECT+UPDATE(role) on onboarding_samples, and full
# CRUD on onboarding_attempts — every statement below stays inside that.
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ulpf_core.validation import report_to_json

if TYPE_CHECKING:
    import psycopg

log = logging.getLogger("onboarding.store")

# Audit ruling: onboarding-generated events use actor = the created_by value.
CREATED_BY = "onboarding"

# TOTAL samples per fingerprint (any role) against the threshold, no active
# rule, no pending candidate, and (no attempt yet OR enough new samples since
# the last attempt) — the retry_new_samples gate.
_READY_SQL = """
SELECT s.fingerprint_id
FROM (
  SELECT fingerprint_id, count(*) AS total
  FROM onboarding_samples
  GROUP BY fingerprint_id
) s
LEFT JOIN onboarding_attempts a ON a.fingerprint_id = s.fingerprint_id
WHERE s.total >= %s
  AND NOT EXISTS (
    SELECT 1 FROM rules r
    WHERE r.fingerprint_id = s.fingerprint_id AND r.status = 'active')
  AND NOT EXISTS (
    SELECT 1 FROM rules r
    WHERE r.fingerprint_id = s.fingerprint_id AND r.status = 'pending_review')
  AND (a.fingerprint_id IS NULL OR s.total - a.samples_seen >= %s)
ORDER BY s.fingerprint_id
"""


def connect_db(url: str) -> psycopg.Connection:
    """psycopg connection for onboarding_role; autocommit per house style."""
    import psycopg  # deferred: unit tests never need psycopg

    return psycopg.connect(url, autocommit=True)


def ready_fingerprints(conn: psycopg.Connection, cfg) -> list[str]:
    """Fingerprint ids with enough samples to attempt, none blocked by an
    active/pending rule, and (for repeat attempts) enough NEW samples."""
    with conn.cursor() as cur:
        cur.execute(_READY_SQL, (cfg.sample_threshold, cfg.retry_new_samples))
        return [row[0] for row in cur.fetchall()]


def load_samples(conn: psycopg.Connection, fingerprint_id: str, limit: int) -> list[dict]:
    """Up to `limit` sample rows for the fingerprint, ordered by
    (captured_at, id) REGARDLESS of current role — the split is re-derived
    from this ordered set on every run (controller ruling)."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, raw_text FROM onboarding_samples "
            "WHERE fingerprint_id = %s ORDER BY captured_at, id LIMIT %s",
            (fingerprint_id, limit),
        )
        return [{"id": row[0], "raw_text": row[1]} for row in cur.fetchall()]


def count_samples(conn: psycopg.Connection, fingerprint_id: str) -> int:
    """TOTAL onboarding_samples rows for the fingerprint (any role) — the
    same units _READY_SQL's s.total is counted in, so samples_seen
    bookkeeping and the retry_new_samples throttle stay commensurate
    (T5-F1: recording the capped loaded count defeated the throttle for
    backlogged fingerprints)."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM onboarding_samples WHERE fingerprint_id = %s",
            (fingerprint_id,),
        )
        return cur.fetchone()[0]


def mark_roles(conn: psycopg.Connection, split: dict[str, list[dict]]) -> None:
    """Persist the re-split scoped by id lists (idempotent on re-run). Always
    three UPDATEs — an empty id list matches nothing but keeps the role
    assignment complete (unused rows are forced back to 'unused')."""
    with conn.transaction(), conn.cursor() as cur:
        for role in ("prompt", "held_out", "unused"):
            ids = [row["id"] for row in split.get(role, [])]
            cur.execute(
                "UPDATE onboarding_samples SET role = %s WHERE id = ANY(%s)",
                (role, ids),
            )
    log.info("roles marked: prompt=%d held_out=%d unused=%d",
             len(split.get("prompt", [])), len(split.get("held_out", [])),
             len(split.get("unused", [])))


def has_active_or_pending(conn: psycopg.Connection,
                          fingerprint_id: str) -> tuple[bool, bool]:
    """(has_active, has_pending) for the fingerprint; the loop skips when
    EITHER is true."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT status FROM rules "
            "WHERE fingerprint_id = %s AND status IN ('active', 'pending_review')",
            (fingerprint_id,),
        )
        statuses = {row[0] for row in cur.fetchall()}
    return "active" in statuses, "pending_review" in statuses


def insert_candidate(conn: psycopg.Connection, rule, report,
                     created_by: str = CREATED_BY) -> int:
    """Store the candidate as ONE pending_review row and audit it.

    version = MAX(existing)+1 for the fingerprint (the rules UNIQUE
    (fingerprint_id, version) contract), validation = the Task 3 report
    verbatim via report_to_json, confidence from the GeneratedRule when the
    rule carries one. The whole sequence (version select -> INSERT -> audit)
    is one transaction.
    """
    from psycopg.types.json import Json  # deferred: keeps psycopg off the test path

    with conn.transaction(), conn.cursor() as cur:
        cur.execute(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM rules WHERE fingerprint_id = %s",
            (rule.fingerprint_id,),
        )
        version = cur.fetchone()[0]
        confidence = getattr(rule, "confidence", None)
        cur.execute(
            "INSERT INTO rules (fingerprint_id, version, pattern, mappings, provenance, "
            "confidence, status, created_by, validation) "
            "VALUES (%s, %s, %s, %s, %s, %s, 'pending_review', %s, %s) RETURNING id",
            (
                rule.fingerprint_id,
                version,
                rule.pattern,
                Json([{"source_field": m.source_field, "ocsf_path": m.ocsf_path}
                      for m in rule.mappings]),
                rule.provenance,
                confidence,
                created_by,
                Json(report_to_json(report)),
            ),
        )
        rule_id = cur.fetchone()[0]
        audit(conn, "candidate_created", rule.fingerprint_id, {
            "rule_id": rule_id,
            "version": version,
            "provenance": rule.provenance,
            "confidence": confidence,
        }, actor=created_by)
    log.info("candidate #%d (v%d) for %s stored as pending_review",
             rule_id, version, rule.fingerprint_id)
    return rule_id


def record_attempt(conn: psycopg.Connection, fingerprint_id: str,
                   samples_seen: int, error: str | None) -> None:
    """Upsert the generation-attempt bookkeeping row (one per fingerprint)."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO onboarding_attempts (fingerprint_id, samples_seen, error) "
            "VALUES (%s, %s, %s) "
            "ON CONFLICT (fingerprint_id) DO UPDATE SET "
            "samples_seen = EXCLUDED.samples_seen, attempted_at = now(), "
            "error = EXCLUDED.error",
            (fingerprint_id, samples_seen, error),
        )


def audit(conn: psycopg.Connection, action: str, entity: str, detail: dict,
          actor: str = CREATED_BY) -> None:
    """One audit_log row; entity is the fingerprint_id (plain string)."""
    from psycopg.types.json import Json  # deferred: keeps psycopg off the test path

    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO audit_log (actor, action, entity, detail) VALUES (%s, %s, %s, %s)",
            (actor, action, entity, Json(detail)),
        )
