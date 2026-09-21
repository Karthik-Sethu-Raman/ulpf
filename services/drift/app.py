# services/drift/app.py — the drift service entrypoint: ONE convergent loop
# (cold path, Postgres only — no Kafka).
#
# Per poll: load active rules, then for each rule one stateless scan —
# fetch_current_view (the DB current view) -> compute_windows (pure, data-only
# horizon) -> window_rows (tier-1) -> insert_windows (idempotent by the
# deterministic window key). Fail-closed posture: drift NEVER blocks anything
# else — every exception is logged with traceback and the loop continues; a
# failed scan is simply retried on the next poll. Tier-2 evaluation, baselines
# and enforcement join this loop in Task 5.
import logging
import threading

from drift.config import Config
from drift.detect import window_rows
from drift.store import (
    ActiveDriftRule,
    baseline_for,
    connect_db,
    fetch_current_view,
    first_window_unmapped,
    insert_windows,
    load_active_rules,
)
from drift.windows import compute_windows

log = logging.getLogger("drift.app")


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
        insert_windows(conn, window_rows(rule, windows))
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
