#!/usr/bin/env python3
"""ULPF schema migration runner.

Plain runner, stdlib + psycopg only. Connects as the admin (superuser)
via the ADMIN_DATABASE_URL environment variable, ensures the
schema_migrations bookkeeping table exists, then applies each .sql file
in --dir that is not yet recorded there. Each migration runs in its own
transaction and is recorded in the same transaction, so a failed
migration leaves no half-applied state and recorded migrations are
never re-applied.
"""

import argparse
import os
import sys
from pathlib import Path

import psycopg


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply pending ULPF SQL migrations.")
    parser.add_argument("--dir", default="deploy/migrations",
                        help="directory containing .sql migration files")
    args = parser.parse_args()

    admin_url = os.environ.get("ADMIN_DATABASE_URL")
    if not admin_url:
        print("error: ADMIN_DATABASE_URL is not set", file=sys.stderr)
        return 2

    migration_dir = Path(args.dir)
    files = sorted(migration_dir.glob("*.sql"))
    if not files:
        print(f"error: no .sql files found in {migration_dir}", file=sys.stderr)
        return 2

    # autocommit=True so each conn.transaction() below is a real top-level
    # transaction that commits per file, independently of later files.
    with psycopg.connect(admin_url, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "name TEXT PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
        )
        cur.execute("SELECT name FROM schema_migrations")
        applied = {row[0] for row in cur.fetchall()}

        pending = [f for f in files if f.name not in applied]
        if not pending:
            print("migrations: up to date")
            return 0

        for path in pending:
            print(f"applying {path.name}")
            try:
                with conn.transaction():
                    cur.execute(path.read_text(encoding="utf-8"))
                    cur.execute(
                        "INSERT INTO schema_migrations (name) VALUES (%s)",
                        (path.name,),
                    )
            except Exception as exc:  # noqa: BLE001 - any per-file failure (SQL, unreadable file) is reported, not a traceback
                print(f"migration {path.name} failed: {exc}", file=sys.stderr)
                return 1
            print(f"applied  {path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
