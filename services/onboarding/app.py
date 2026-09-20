# services/onboarding/app.py — the candidate-generation loop (cold path,
# serial per fingerprint; the hot path is never touched from here).
#
# Per fingerprint: has_active_or_pending guard -> load_samples -> assign_roles
# -> mark_roles -> audit(samples_split) -> JSON fast-path (ALL prompt lines
# parse as JSON) or SLM generate_candidate -> validate_candidate -> passed:
# insert_candidate (audits candidate_created) / failed: record_attempt +
# audit(candidate_failed). Every DB failure and SLM unreachability is logged
# and the loop continues — fail-closed posture: onboarding pends, the hot
# path stays untouched.
import logging
import threading

from ulpf_core.validation import validate_candidate

from onboarding.config import Config
from onboarding.generate import (
    OllamaClient,
    generate_candidate,
    generate_json_rule,
    is_json_line,
)
from onboarding.samples import assign_roles
from onboarding.store import (
    audit,
    connect_db,
    has_active_or_pending,
    insert_candidate,
    load_samples,
    mark_roles,
    ready_fingerprints,
    record_attempt,
)

log = logging.getLogger("onboarding.app")


def process_fingerprint(cfg: Config, fingerprint_id: str) -> bool:
    """One candidate cycle for one fingerprint; True iff a candidate was
    stored. Any failure is logged here and reported as False — never raised
    into the loop."""
    with connect_db(cfg.database_url) as conn:
        has_active, has_pending = has_active_or_pending(conn, fingerprint_id)
        if has_active or has_pending:
            log.info("skip %s: active or pending rule exists", fingerprint_id)
            return False
        rows = load_samples(conn, fingerprint_id, cfg.sample_threshold)

    if len(rows) < cfg.prompt_size + cfg.held_out_size:
        log.info("skip %s: %d samples below split size", fingerprint_id, len(rows))
        return False

    split = assign_roles(rows, cfg.prompt_size, cfg.held_out_size)
    prompt_lines = [row["raw_text"] for row in split["prompt"]]
    held_out_lines = [row["raw_text"] for row in split["held_out"]]

    with connect_db(cfg.database_url) as conn:
        mark_roles(conn, split)
        audit(conn, "samples_split", fingerprint_id, {
            "prompt": len(split["prompt"]),
            "held_out": len(split["held_out"]),
            "unused": len(split["unused"]),
        })

    try:
        if all(is_json_line(line) for line in prompt_lines):
            # JSON fast-path: deterministic alias matching, NO model call. All
            # samples (prompt + held-out) feed the confidence statistic — the
            # rule derives from key-name aliases, so there is nothing to leak
            # into it and the confidence covers the held-out split too.
            rule = generate_json_rule(fingerprint_id, prompt_lines + held_out_lines)
        else:
            client = OllamaClient(cfg.ollama_url, cfg.ollama_model)
            rule = generate_candidate(fingerprint_id, prompt_lines, client)
    except Exception as exc:
        # GenerationError / SLM unreachable / JSON edge — fail closed. Full
        # traceback to the log; the summary goes to the attempt record.
        log.exception("generation failed for %s", fingerprint_id)
        _record_failure(cfg, fingerprint_id, len(rows), f"generation failed: {exc}")
        return False

    report = validate_candidate(rule, prompt_lines, held_out_lines)
    if not report.passed:
        summary = "; ".join(report.notes[:3]) or "validation failed"
        _record_failure(cfg, fingerprint_id, len(rows), f"validation failed: {summary}")
        return False

    with connect_db(cfg.database_url) as conn:
        # insert_candidate audits candidate_created itself (ruling: actor =
        # the created_by value); the audit detail carries the REAL version —
        # the rule object's version field is only the generation placeholder.
        rule_id = insert_candidate(conn, rule, report)
    log.info("candidate stored for %s (rules.id=%s, provenance=%s, confidence=%s)",
             fingerprint_id, rule_id, rule.provenance, getattr(rule, "confidence", None))
    return True


def _record_failure(cfg: Config, fingerprint_id: str, samples_seen: int,
                    error: str) -> None:
    """record_attempt + audit(candidate_failed); itself failure-tolerant —
    a bookkeeping write must never kill the loop."""
    log.warning("candidate failed for %s: %s", fingerprint_id, error)
    try:
        with connect_db(cfg.database_url) as conn:
            record_attempt(conn, fingerprint_id, samples_seen, error)
            audit(conn, "candidate_failed", fingerprint_id,
                  {"error": error, "samples_seen": samples_seen})
    except Exception:
        log.exception("failed to record the attempt for %s", fingerprint_id)


def run_candidate_loop(cfg: Config, stop: threading.Event) -> None:
    """Poll for ready fingerprints and run one candidate cycle each, serially
    (cold path). `stop.set()` ends the loop promptly (wait() is sliced by the
    event). Every exception is logged; the loop continues — convergence is
    re-attempted on the next poll."""
    log.info("onboarding candidate loop started (threshold=%d, poll=%.1fs, "
             "slm=%s@%s)", cfg.sample_threshold, cfg.onboarding_poll_s,
             cfg.ollama_model, cfg.ollama_url)
    while not stop.is_set():
        try:
            with connect_db(cfg.database_url) as conn:
                fingerprints = ready_fingerprints(conn, cfg)
            for fingerprint_id in fingerprints:
                if stop.is_set():
                    break
                try:
                    process_fingerprint(cfg, fingerprint_id)
                except Exception:
                    log.exception("fingerprint %s failed; continuing", fingerprint_id)
        except Exception:
            log.exception("candidate loop iteration failed; will retry")
        stop.wait(cfg.onboarding_poll_s)
    log.info("onboarding candidate loop stopped")


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    cfg = Config.from_env()
    try:
        run_candidate_loop(cfg, threading.Event())
    except KeyboardInterrupt:
        log.info("shutdown requested")


if __name__ == "__main__":
    main()
