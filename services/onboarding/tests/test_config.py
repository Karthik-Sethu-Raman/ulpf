# services/onboarding/tests/test_config.py — pins the binding compose ruling
# (SLM tier qwen3:4b behind ollama-4b, compose-internal onboarding DSN, and
# the exact env names Task 11 sets in docker-compose).
from onboarding.config import Config


def test_defaults_match_the_compose_ruling():
    cfg = Config()
    assert cfg.database_url == "postgresql://onboarding_role:onboarding_dev@postgres:5432/ulpf"
    assert cfg.ollama_url == "http://ollama-4b:11434"
    assert cfg.ollama_model == "qwen3:4b"
    assert cfg.sample_threshold == 20
    assert cfg.prompt_size == 5
    assert cfg.held_out_size == 15
    assert cfg.retry_new_samples == 10
    assert cfg.onboarding_poll_s == 5.0
    assert cfg.reparse_poll_s == 2.0
    assert cfg.reparse_batch == 500


def test_from_env_reads_exactly_the_three_compose_names(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://x:x@db:5432/ulpf")
    monkeypatch.setenv("OLLAMA_URL", "http://slm:11434")
    monkeypatch.setenv("OLLAMA_MODEL", "other:7b")
    cfg = Config.from_env()
    assert cfg.database_url == "postgresql://x:x@db:5432/ulpf"
    assert cfg.ollama_url == "http://slm:11434"
    assert cfg.ollama_model == "other:7b"
    # Non-env fields keep their defaults.
    assert cfg.sample_threshold == 20


def test_from_env_without_env_keeps_defaults(monkeypatch):
    for name in ("DATABASE_URL", "OLLAMA_URL", "OLLAMA_MODEL"):
        monkeypatch.delenv(name, raising=False)
    cfg = Config.from_env()
    assert cfg == Config()
