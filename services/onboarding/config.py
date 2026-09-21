# services/onboarding/config.py — onboarding service configuration.
#
# Compose env contract (Task 11 sets exactly these names): DATABASE_URL,
# OLLAMA_URL, OLLAMA_MODEL. Defaults are the compose-internal endpoints
# (binding ruling): the DSN follows M1's per-service constant pattern (env
# overrides), the SLM tier is qwen3:4b behind ollama-4b:11434.
import os
from dataclasses import dataclass


@dataclass
class Config:
    database_url: str = "postgresql://onboarding_role:onboarding_dev@postgres:5432/ulpf"
    ollama_url: str = "http://ollama-4b:11434"
    ollama_model: str = "qwen3:4b"
    sample_threshold: int = 20
    prompt_size: int = 5
    held_out_size: int = 15
    retry_new_samples: int = 10
    onboarding_poll_s: float = 5.0
    reparse_poll_s: float = 2.0
    reparse_batch: int = 500

    @classmethod
    def from_env(cls) -> "Config":
        base = cls()
        return cls(
            database_url=os.environ.get("DATABASE_URL", base.database_url),
            ollama_url=os.environ.get("OLLAMA_URL", base.ollama_url),
            ollama_model=os.environ.get("OLLAMA_MODEL", base.ollama_model),
        )
