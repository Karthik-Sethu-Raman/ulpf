# services/gateway/writes.py — the gateway's write path (Task 7): the rule
# lifecycle transitions behind migration 003's least-privilege rules_role.
#
# The grant surface IS the design: rules_role may INSERT rules, UPDATE ONLY
# (status, activated_at, deactivated_at), INSERT audit_log, and SELECT
# onboarding_samples. Content columns are UPDATE-denied — so approve-with-edits
# INSERTs a fresh version row and flips the draft candidate to rejected; it can
# never rewrite content in place.
#
# Version minting (X-b′): candidates are created pending_review at
# MAX(version)+1 for the fingerprint; plain approve activates the candidate row
# itself (status + timestamps only); approve-with-edits INSERTs version = MAX+1
# with the edited content and consumes the draft. Versions are NOT gap-free —
# documented, accepted.
#
# Partial-unique ordering gotcha: rules_one_active is a partial unique index,
# checked per-statement and not deferrable — the prior active row MUST be
# flipped to superseded BEFORE the new row goes active, or the later statement
# raises a unique violation.
#
# House style (T7): connections run AUTOCOMMIT; each public function wraps
# exactly one `with conn.transaction():` block; every mutation is paired with
# an audit INSERT (entity = the fingerprint_id; gateway lifecycle actions:
# rule_approved, rule_rejected, rule_deactivated, rule_reactivated; actor is a
# request field defaulting to "anonymous" — no auth in MVP). psycopg is
# imported lazily so unit tests drive everything through fake conns (never a
# live DB; mirrors services/onboarding/store.py).
from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from ulpf_core.models import Mapping, Rule
from ulpf_core.validation import report_to_json, validate_candidate

if TYPE_CHECKING:
    import psycopg

log = logging.getLogger("gateway.writes")


class WriteError(Exception):
    """Base for gateway write failures; app maps subclasses onto HTTP codes."""


class NotFoundError(WriteError):
    """404: unknown candidate/rule/fingerprint."""


class ConflictError(WriteError):
    """409: not pending, another version already active, or a lost insert race."""


class ValidationError(WriteError):
    """422: the deterministic gate rejected the candidate; carries the report
    so the API body can render checks + notes."""

    def __init__(self, report):
        super().__init__("candidate failed validation")
        self.report = report

    @property
    def checks(self) -> dict:
        return self.report.checks

    @property
    def notes(self) -> list:
        return self.report.notes


def _connect_write() -> psycopg.Connection:
    """One connection per request, as rules_role; dict rows and AUTOCOMMIT per
    house style (multi-statement operations wrap one transaction() block)."""
    import psycopg
    from psycopg.rows import dict_row

    return psycopg.connect(os.environ["WRITE_DATABASE_URL"], row_factory=dict_row,
                           autocommit=True)


# --- shared statement pieces ---------------------------------------------------

_CANDIDATE_SQL = (
    "SELECT id, fingerprint_id, version, status, pattern, mappings, provenance, confidence "
    "FROM rules WHERE id = %s AND fingerprint_id = %s"
)
_SAMPLES_SQL = (
    "SELECT raw_text, role FROM onboarding_samples "
    "WHERE fingerprint_id = %s AND role IN ('prompt','held_out') "
    "ORDER BY captured_at, id"
)
_AUDIT_SQL = "INSERT INTO audit_log (actor, action, entity, detail) VALUES (%s, %s, %s, %s)"


# --- plumbing -------------------------------------------------------------------

def _run(op, conn, /, *args):
    """Run one txn-wrapped operation; open/close the connection when none is
    injected (tests always inject a fake). IntegrityError on the candidate
    INSERT — a concurrent writer won the version/pending race — retries the
    whole operation ONCE, then surfaces ConflictError (409)."""
    if conn is None:
        conn = _connect_write()
        try:
            return _with_insert_retry(op, conn, *args)
        finally:
            conn.close()
    return _with_insert_retry(op, conn, *args)


def _with_insert_retry(op, conn, *args):
    import psycopg

    try:
        return op(conn, *args)
    except psycopg.IntegrityError:
        log.warning("concurrent candidate insert lost the race; retrying once")
        try:
            return op(conn, *args)
        except psycopg.IntegrityError as exc:
            raise ConflictError(
                "concurrent modification; the rule state changed — retry"
            ) from exc


def _audit(cur, action: str, entity: str, detail: dict, *, actor: str) -> None:
    from psycopg.types.json import Json  # deferred: keeps psycopg off the import path

    cur.execute(_AUDIT_SQL, (actor, action, entity, Json(detail)))


def _load_candidate(cur, fingerprint_id: str, candidate_id: int) -> dict:
    cur.execute(_CANDIDATE_SQL, (candidate_id, fingerprint_id))
    row = cur.fetchone()
    if row is None:
        raise NotFoundError(
            f"candidate {candidate_id} not found for fingerprint {fingerprint_id!r}")
    return row


def _require_pending(candidate: dict) -> None:
    if candidate["status"] != "pending_review":
        raise ConflictError(
            f"candidate {candidate['id']} is {candidate['status']!r}, not pending_review")


def _revalidation_lines(cur, fingerprint_id: str) -> tuple[list, list]:
    """(prompt_lines, held_out_lines) in capture order — the gate's inputs."""
    cur.execute(_SAMPLES_SQL, (fingerprint_id,))
    prompt: list[str] = []
    held_out: list[str] = []
    for row in cur.fetchall():
        (prompt if row["role"] == "prompt" else held_out).append(row["raw_text"])
    return prompt, held_out


def _supersede_active(cur, fingerprint_id: str):
    """Flip the fingerprint's active row to superseded FIRST (partial-unique
    gotcha: the index is per-statement, so activating a new row while the old
    one is still active would raise). Returns the prior active version, or
    None when nothing was active."""
    cur.execute(
        "UPDATE rules SET status = 'superseded' "
        "WHERE fingerprint_id = %s AND status = 'active' RETURNING version",
        (fingerprint_id,),
    )
    row = cur.fetchone()
    return row["version"] if row else None


def _next_version(cur, fingerprint_id: str) -> int:
    """MAX(version)+1 for the fingerprint, computed INSIDE the txn."""
    cur.execute(
        "SELECT COALESCE(MAX(version), 0) + 1 AS next_version FROM rules "
        "WHERE fingerprint_id = %s",
        (fingerprint_id,),
    )
    return cur.fetchone()["next_version"]


def _insert_rule(cur, *, fingerprint_id: str, version: int, pattern: str, mappings,
                 provenance: str, confidence, status: str, created_by: str,
                 report) -> int:
    from psycopg.types.json import Json

    # status is a module-controlled literal ('active' / 'pending_review'), never
    # request input — interpolated to match the onboarding store's INSERT shape
    # (the rules status CHECK constraint is the real guard).
    cur.execute(
        "INSERT INTO rules (fingerprint_id, version, pattern, mappings, provenance, "
        f"confidence, status, created_by, validation) "
        f"VALUES (%s, %s, %s, %s, %s, %s, '{status}', %s, %s) RETURNING id",
        (fingerprint_id, version, pattern, Json(mappings), provenance, confidence,
         created_by, Json(report_to_json(report))),
    )
    return cur.fetchone()["id"]


# --- approve --------------------------------------------------------------------

def approve_candidate(fingerprint_id: str, candidate_id: int, *, actor: str = "anonymous",
                      reason: str | None = None, edited_mappings=None, override=None,
                      conn: psycopg.Connection | None = None) -> dict:
    """Approve a pending candidate — the ONE activation path.

    Plain approve flips the candidate row itself to active (status + timestamps
    only; content columns are UPDATE-denied by grant). With edited_mappings or
    a full override, the edited rule is revalidated through the deterministic
    gate against the fingerprint's samples, a NEW row version = MAX+1 is
    INSERTed already active (provenance 'slm-edited' / 'human'), and the draft
    candidate is flipped to rejected (audited with consumed_by_edit)."""
    return _run(_approve_once, conn, fingerprint_id, candidate_id, actor, reason,
                edited_mappings, override)


def _edited_content(candidate: dict, edited_mappings, override):
    """(pattern, mappings, provenance, confidence) for the approve-with-edits
    row: edited_mappings keep the candidate pattern + confidence with
    provenance 'slm-edited'; a full override replaces pattern and mappings
    wholesale with provenance 'human' (the SLM confidence no longer describes
    that content)."""
    if override is not None:
        return override["pattern"], override["mappings"], "human", None
    return candidate["pattern"], edited_mappings, "slm-edited", candidate["confidence"]


def _approve_once(conn, fingerprint_id, candidate_id, actor, reason, edited_mappings,
                  override):
    with conn.transaction(), conn.cursor() as cur:
        candidate = _load_candidate(cur, fingerprint_id, candidate_id)
        _require_pending(candidate)

        if edited_mappings is None and override is None:
            # Plain approve: supersede the prior active row BEFORE this one goes
            # active (partial-unique gotcha), then flip status + timestamps only.
            prior_version = _supersede_active(cur, fingerprint_id)
            cur.execute(
                "UPDATE rules SET status = 'active', activated_at = now() WHERE id = %s",
                (candidate_id,),
            )
            _audit(cur, "rule_approved", fingerprint_id, {
                "rule_id": candidate_id,
                "version": candidate["version"],
                "actor": actor,
                "reason": reason,
                "prior_version": prior_version,
            }, actor=actor)
            return {"rule_id": candidate_id, "version": candidate["version"],
                    "status": "active"}

        # Approve-with-edits: validate FIRST (a failing gate must not mutate
        # anything), then supersede, mint the new active version, consume the draft.
        pattern, mappings, provenance, confidence = _edited_content(
            candidate, edited_mappings, override)
        prompt_lines, held_out_lines = _revalidation_lines(cur, fingerprint_id)
        rule = Rule(fingerprint_id=fingerprint_id, version=candidate["version"],
                    pattern=pattern, provenance=provenance,
                    mappings=[Mapping(**m) for m in mappings])
        report = validate_candidate(rule, prompt_lines, held_out_lines)
        if not report.passed:
            raise ValidationError(report)

        prior_version = _supersede_active(cur, fingerprint_id)
        version = _next_version(cur, fingerprint_id)
        new_id = _insert_rule(cur, fingerprint_id=fingerprint_id, version=version,
                              pattern=pattern, mappings=mappings, provenance=provenance,
                              confidence=confidence, status="active", created_by=actor,
                              report=report)
        cur.execute("UPDATE rules SET status = 'rejected' WHERE id = %s", (candidate_id,))
        _audit(cur, "rule_approved", fingerprint_id, {
            "rule_id": new_id,
            "version": version,
            "actor": actor,
            "reason": reason,
            "prior_version": prior_version,
            "consumed_by_edit": version,
            "consumed_candidate_id": candidate_id,
            "provenance": provenance,
        }, actor=actor)
        return {"rule_id": new_id, "version": version, "status": "active"}


# --- reject ---------------------------------------------------------------------

def reject_candidate(fingerprint_id: str, candidate_id: int, *, actor: str = "anonymous",
                     reason: str | None = None,
                     conn: psycopg.Connection | None = None) -> dict:
    """Reject a pending candidate (terminal)."""
    return _run(_reject_once, conn, fingerprint_id, candidate_id, actor, reason)


def _reject_once(conn, fingerprint_id, candidate_id, actor, reason):
    with conn.transaction(), conn.cursor() as cur:
        candidate = _load_candidate(cur, fingerprint_id, candidate_id)
        _require_pending(candidate)
        cur.execute("UPDATE rules SET status = 'rejected' WHERE id = %s", (candidate_id,))
        _audit(cur, "rule_rejected", fingerprint_id, {
            "rule_id": candidate_id,
            "version": candidate["version"],
            "actor": actor,
            "reason": reason,
        }, actor=actor)
    return {"status": "rejected"}


# --- manual authoring (step 1 of 2; approval rides approve_candidate) ------------

def create_manual_candidate(fingerprint_id: str, pattern: str, mappings, *,
                            actor: str = "anonymous", confidence: float | None = None,
                            conn: psycopg.Connection | None = None) -> dict:
    """Validate a hand-written rule through the SAME deterministic gate as SLM
    candidates and store it pending_review (provenance 'human', created_by =
    actor). A human then approves it through the same approve endpoint — one
    activation path, uniform audit. Validation failure writes nothing and
    raises ValidationError (app -> 422 with checks + notes). With no samples
    the gate degrades to pass-with-note, so an unseen format can be authored."""
    return _run(_create_manual_once, conn, fingerprint_id, pattern, list(mappings),
                actor, confidence)


def _create_manual_once(conn, fingerprint_id, pattern, mappings, actor, confidence):
    with conn.transaction(), conn.cursor() as cur:
        prompt_lines, held_out_lines = _revalidation_lines(cur, fingerprint_id)
        # version=1 is a generation placeholder; the real version is minted below.
        rule = Rule(fingerprint_id=fingerprint_id, version=1, pattern=pattern,
                    provenance="human", mappings=[Mapping(**m) for m in mappings])
        report = validate_candidate(rule, prompt_lines, held_out_lines)
        if not report.passed:
            raise ValidationError(report)
        version = _next_version(cur, fingerprint_id)
        rule_id = _insert_rule(cur, fingerprint_id=fingerprint_id, version=version,
                               pattern=pattern, mappings=mappings, provenance="human",
                               confidence=confidence, status="pending_review",
                               created_by=actor, report=report)
        _audit(cur, "candidate_created", fingerprint_id, {
            "rule_id": rule_id,
            "version": version,
            "provenance": "human",
            "confidence": confidence,
        }, actor=actor)
        return {"rule_id": rule_id, "version": version, "status": "pending_review"}


# --- deactivate / reactivate ------------------------------------------------------

def deactivate_rule(fingerprint_id: str, *, actor: str = "anonymous",
                    reason: str | None = None,
                    conn: psycopg.Connection | None = None) -> dict:
    """Deactivate the fingerprint's ACTIVE rule (fingerprint reverts to
    raw-only; samples re-accumulate and onboarding re-runs)."""
    return _run(_deactivate_once, conn, fingerprint_id, actor, reason)


def _deactivate_once(conn, fingerprint_id, actor, reason):
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(
            "SELECT id, version FROM rules "
            "WHERE fingerprint_id = %s AND status = 'active'",
            (fingerprint_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise NotFoundError(f"no active rule for fingerprint {fingerprint_id!r}")
        cur.execute(
            "UPDATE rules SET status = 'deactivated', deactivated_at = now() WHERE id = %s",
            (row["id"],),
        )
        _audit(cur, "rule_deactivated", fingerprint_id, {
            "rule_id": row["id"],
            "version": row["version"],
            "actor": actor,
            "reason": reason,
        }, actor=actor)
        return {"rule_id": row["id"], "version": row["version"],
                "status": "deactivated"}


def reactivate_rule(rule_id: int, *, actor: str = "anonymous",
                    reason: str | None = None,
                    conn: psycopg.Connection | None = None) -> dict:
    """Reactivate a rule row (status -> active, activated_at = now); 409 when
    another version of the fingerprint is already active (rules_one_active)."""
    return _run(_reactivate_once, conn, rule_id, actor, reason)


def _reactivate_once(conn, rule_id, actor, reason):
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(
            "SELECT id, fingerprint_id, version, status FROM rules WHERE id = %s",
            (rule_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise NotFoundError(f"rule {rule_id} not found")
        if row["status"] == "active":
            raise ConflictError(f"rule {rule_id} is already active")
        cur.execute(
            "SELECT id FROM rules "
            "WHERE fingerprint_id = %s AND status = 'active' AND id <> %s",
            (row["fingerprint_id"], rule_id),
        )
        other = cur.fetchone()
        if other is not None:
            raise ConflictError(
                f"rule {other['id']} is already active for fingerprint "
                f"{row['fingerprint_id']!r}")
        cur.execute(
            "UPDATE rules SET status = 'active', activated_at = now() WHERE id = %s",
            (rule_id,),
        )
        _audit(cur, "rule_reactivated", row["fingerprint_id"], {
            "rule_id": rule_id,
            "version": row["version"],
            "actor": actor,
            "reason": reason,
        }, actor=actor)
        return {"rule_id": rule_id, "version": row["version"], "status": "active"}
