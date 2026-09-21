# services/drift/tests/test_config.py — pins the binding env-knob ruling
# (deploy/.env.example names, compose-internal drift_role DSN, defaults equal
# to the .env.example values).
from drift.config import Config


def test_defaults_match_the_env_example_ruling():
    cfg = Config()
    assert cfg.database_url == "postgresql://drift_role:drift_dev@postgres:5432/ulpf"
    assert cfg.window_count == 1000
    assert cfg.window_time_s == 600
    assert cfg.baseline_windows == 10
    assert cfg.poll_s == 5.0


def test_from_env_reads_exactly_the_five_compose_names(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://x:x@db:5432/ulpf")
    monkeypatch.setenv("ULPF_DRIFT_WINDOW_COUNT", "2500")
    monkeypatch.setenv("ULPF_DRIFT_WINDOW_TIME_S", "300")
    monkeypatch.setenv("ULPF_DRIFT_BASELINE_WINDOWS", "20")
    monkeypatch.setenv("ULPF_DRIFT_POLL_S", "0.5")
    cfg = Config.from_env()
    assert cfg.database_url == "postgresql://x:x@db:5432/ulpf"
    assert cfg.window_count == 2500
    assert cfg.window_time_s == 300
    assert cfg.baseline_windows == 20
    assert cfg.poll_s == 0.5


def test_from_env_without_env_keeps_defaults(monkeypatch):
    for name in ("DATABASE_URL", "ULPF_DRIFT_WINDOW_COUNT", "ULPF_DRIFT_WINDOW_TIME_S",
                 "ULPF_DRIFT_BASELINE_WINDOWS", "ULPF_DRIFT_POLL_S"):
        monkeypatch.delenv(name, raising=False)
    assert Config.from_env() == Config()
