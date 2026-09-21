# services/drift/config.py — drift service configuration.
#
# Compose env contract (Task 1 pinned these exact names in deploy/.env.example
# and docker-compose passes them through): DATABASE_URL plus the four
# ULPF_DRIFT_* knobs. Defaults equal the .env.example values (binding ruling);
# the DSN follows the per-service constant pattern (env overrides).
import os
from dataclasses import dataclass


@dataclass
class Config:
    database_url: str = "postgresql://drift_role:drift_dev@postgres:5432/ulpf"
    window_count: int = 1000        # rows per window (count-close boundary)
    window_time_s: int = 600        # close a window whose FIRST row ages out
    baseline_windows: int = 10      # windows aggregated into the baseline (Task 5)
    poll_s: float = 5.0

    @classmethod
    def from_env(cls) -> "Config":
        base = cls()
        return cls(
            database_url=os.environ.get("DATABASE_URL", base.database_url),
            window_count=int(os.environ.get("ULPF_DRIFT_WINDOW_COUNT",
                                            base.window_count)),
            window_time_s=int(os.environ.get("ULPF_DRIFT_WINDOW_TIME_S",
                                             base.window_time_s)),
            baseline_windows=int(os.environ.get("ULPF_DRIFT_BASELINE_WINDOWS",
                                                base.baseline_windows)),
            poll_s=float(os.environ.get("ULPF_DRIFT_POLL_S", base.poll_s)),
        )
