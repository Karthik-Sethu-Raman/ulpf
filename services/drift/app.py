# services/drift/app.py — the drift service entrypoint: ONE convergent loop
# (cold path, Postgres only — no Kafka).
#
# Per poll: load active rules, then for each rule one stateless scan, in the
# frozen order — fetch_current_view (the DB current view) -> compute_windows
# (pure, data-only horizon) -> evaluate_window (tier-1 always; tier-2 only
# against an existing baseline profile) -> record_windows (idempotent by the
# deterministic window key) -> FIRST baseline insert when the Nth baseline
# window just closed -> enforce_findings worst-first. Ruling: on the
# establishing scan itself the baseline profile does not exist yet at
# evaluation time, so that scan is tier-1-only by construction — the windows
# BEYOND the Nth on that same scan keep their first-recorded tier-1 severity
# (ON CONFLICT DO NOTHING), but the next scan re-evaluates the whole current
# view WITH the profile and enforcement converges. Fail-closed posture: drift
# NEVER blocks anything else — every exception is logged with traceback and
# the loop continues; a failed scan is simply retried on the next poll.
import logging
import threading

from drift.config import Config
from drift.detect import Finding, aggregate_baseline, evaluate_window
from drift.enforce import enforce_findings, record_windows
from drift.store import (
    ActiveDriftRule,
    baseline_for,
    connect_db,
    fetch_current_view,
    fetch_window_history,
    first_window_unmapped,
    insert_baseline,
    load_active_rules,
)
from drift.windows import compute_windows

log = logging.getLogger("drift.app")


def establish_baseline(conn, cfg: Config, rule: ActiveDriftRule) -> bool:
    """The FIRST baseline insert, once due (R-M3-7): after this scan's windows
    are recorded, aggregate the version's first cfg.baseline_windows closed
    windows and INSERT the profiles once. Returns False while fewer than N
    windows exist; insert_baseline's existence guard + ON CONFLICT make later
    scans no-ops (the 11th scan never re-inserts), and a version bump re-arms
    naturally — the new (fingerprint, version) has no profile, so tier-1-only
    baseline windows accumulate again."""
    history = fetch_window_history(conn, rule.fingerprint_id, rule.version)
    profiles = aggregate_baseline(history, baseline_windows=cfg.baseline_windows)
    if profiles is None:
        return False
    return insert_baseline(conn, rule.fingerprint_id, rule.version,
                           profiles, cfg.baseline_windows)


def scan_rule(cfg: Config, rule: ActiveDriftRule) -> int:
    """One scan for one active rule; returns the number of CLOSED windows
    found (0 when the current view holds nothing provably complete). One
    connection covers the whole scan (the reparse per-sweep pattern)."""
    with connect_db(cfg.database_url) as conn:
        rows = fetch_current_view(conn, rule.fingerprint_id, rule.version)
        baseline = baseline_for(conn, rule.fingerprint_id, rule.version)
        known = (first_window_unmapped(conn, rule.fingerprint_id, rule.version)
                 if baseline is not None else None)
        windows = compute_windows(
            rows,
            count_window=cfg.window_count,
            time_window_s=cfg.window_time_s,
            mapped_paths=tuple(dict.fromkeys(m.ocsf_path for m in rule.mappings)),
            known_unmapped=known,
        )
        if not windows:
            return 0
        findings: list[Finding] = []
        for win in windows:
            window_findings = evaluate_window(
                win, baseline, rule_quarantined=rule.quarantined_fields)
            record_windows(conn, rule, window_findings, win)
            findings.extend(window_findings)
        if baseline is None:
            establish_baseline(conn, cfg, rule)
        enforce_findings(conn, rule, findings)
    log.info("scanned %s v%d: %d closed window(s) over %d current-view row(s)",
             rule.fingerprint_id, rule.version, len(windows), len(rows))
    return len(windows)


def run_drift_loop(cfg: Config, stop: threading.Event) -> None:
    """Poll for active rules and scan each, serially (cold path). `stop.set()`
    ends the loop promptly (wait() is sliced by the event). Every exception is
    logged; the loop continues — windows are recomputed from the DB next poll,
    so a failed scan self-heals (fail-closed, never blocks the hot path)."""
    log.info("drift loop started (window_count=%d, window_time_s=%d, poll=%.1fs)",
             cfg.window_count, cfg.window_time_s, cfg.poll_s)
    while not stop.is_set():
        try:
            with connect_db(cfg.database_url) as conn:
                rules = load_active_rules(conn)
            for rule in rules:
                if stop.is_set():
                    break
                try:
                    scan_rule(cfg, rule)
                except Exception:
                    log.exception("drift scan failed for %s v%d; continuing",
                                  rule.fingerprint_id, rule.version)
        except Exception:
            log.exception("drift loop iteration failed; will retry")
        stop.wait(cfg.poll_s)
    log.info("drift loop stopped")


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    cfg = Config.from_env()
    # ONE loop, run in the MAIN thread (controller ruling — unlike onboarding's
    # two daemon loops): SIGINT lands here directly and ends the wait-sliced
    # loop; run_drift_loop stays daemon-friendly for any hosting thread.
    stop = threading.Event()
    try:
        run_drift_loop(cfg, stop)
    except KeyboardInterrupt:
        stop.set()
        log.info("shutdown requested")


if __name__ == "__main__":
    main()
