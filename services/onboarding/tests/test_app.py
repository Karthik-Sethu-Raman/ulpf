# services/onboarding/tests/test_app.py — wiring test for the failure path
# (T5-F1): samples_seen handed to record_attempt/audit must be the
# fingerprint's TOTAL sample count (store.count_samples), NOT the capped
# loaded count — otherwise the retry_new_samples throttle never engages for
# backlogged fingerprints. Minimal monkeypatch style: app.py imported its
# store collaborators by name, so patching the app module's globals is
# enough to observe the wiring.
from onboarding import app


class FakeStoreConn:
    """Just the context-manager role of a psycopg connection."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_failure_path_records_total_sample_count(monkeypatch):
    seen = {}

    def fake_connect_db(url):
        return FakeStoreConn()

    def fake_count_samples(conn, fp):
        return 45  # TOTAL rows: e.g. 30 piled up while the SLM was down

    def fake_record_attempt(conn, fp, samples_seen, error):
        seen["attempt"] = (fp, samples_seen, error)

    def fake_audit(conn, action, entity, detail, actor="onboarding"):
        seen.setdefault("audits", []).append((action, entity, detail))

    monkeypatch.setattr(app, "connect_db", fake_connect_db)
    monkeypatch.setattr(app, "count_samples", fake_count_samples)
    monkeypatch.setattr(app, "record_attempt", fake_record_attempt)
    monkeypatch.setattr(app, "audit", fake_audit)

    app._record_failure(app.Config(), "fp_backlog", "validation failed: boom")

    assert seen["attempt"] == ("fp_backlog", 45, "validation failed: boom")
    assert seen["audits"] == [
        ("candidate_failed", "fp_backlog",
         {"error": "validation failed: boom", "samples_seen": 45}),
    ]


def test_main_wires_both_convergent_loops(monkeypatch):
    # Controller ruling: the onboarding service runs BOTH convergent loops
    # (candidate generation + R11 backlog re-parse) as daemon threads sharing
    # one stop handle. Both fakes return immediately, so main()'s join loop
    # drains and returns — no threading harness needed.
    invoked = []

    def fake_candidate(cfg, stop):
        invoked.append(("candidate", cfg, stop))

    def fake_reparse(cfg, stop):
        invoked.append(("reparse", cfg, stop))

    monkeypatch.setattr(app, "run_candidate_loop", fake_candidate)
    monkeypatch.setattr(app, "run_reparse_loop", fake_reparse)

    app.main()

    assert sorted(name for name, _, _ in invoked) == ["candidate", "reparse"]
    # One Config and ONE shared threading.Event stop handle across both loops.
    assert len({id(cfg) for _, cfg, _ in invoked}) == 1
    assert len({id(stop) for _, _, stop in invoked}) == 1
