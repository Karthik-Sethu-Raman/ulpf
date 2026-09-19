"""
P3 — Ingestion + Raw Storage + Traceability

This module is the front door of the ULPF pipeline. Every raw log line,
no matter its format or eventual fate downstream, passes through
ingest_line() first and is stored byte-for-byte untouched in SQLite
before anything else happens to it.
"""
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from schemas.schemas import RawEvent

# Single-file SQLite database — sits alongside this module.
# No server, no setup: sqlite3 is part of the Python standard library.
DB_PATH = Path(__file__).parent / "raw_events.db"


def _get_connection() -> sqlite3.Connection:
    """
    Open a connection to the local SQLite file and make sure the
    raw_events table exists. Safe to call every time — CREATE TABLE
    IF NOT EXISTS is a no-op once the table is already there.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS raw_events (
            raw_id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            timestamp_ingested TEXT NOT NULL,
            format_guess TEXT NOT NULL,
            raw_text TEXT NOT NULL
        )
        """
    )
    return conn


def ingest_line(raw_text: str, source_id: str, format_guess: str = "unknown") -> RawEvent:
    """
    Assign a unique raw_id, stamp timestamp_ingested (now, ISO8601),
    store raw_text verbatim to disk, and return the RawEvent object.

    This must be called for every incoming line, no exceptions — even if
    downstream parsing later fails. It does not interpret, clean, or
    validate raw_text in any way; that is deliberate.
    """
    raw_id = f"raw_{uuid.uuid4().hex[:8]}"
    timestamp_ingested = datetime.now(timezone.utc).isoformat()

    event = RawEvent(
        raw_id=raw_id,
        source_id=source_id,
        timestamp_ingested=timestamp_ingested,
        format_guess=format_guess,
        raw_text=raw_text,
    )

    conn = _get_connection()
    try:
        conn.execute(
            """
            INSERT INTO raw_events
                (raw_id, source_id, timestamp_ingested, format_guess, raw_text)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                event.raw_id,
                event.source_id,
                event.timestamp_ingested,
                event.format_guess,
                event.raw_text,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    return event


def get_raw_event(raw_id: str) -> RawEvent:
    """
    Look up and return a previously ingested RawEvent by its raw_id.
    Raises KeyError if no such raw_id exists — callers (e.g. P4's UI)
    should handle that explicitly rather than get a silent None back.
    """
    conn = _get_connection()
    try:
        cursor = conn.execute(
            """
            SELECT raw_id, source_id, timestamp_ingested, format_guess, raw_text
            FROM raw_events
            WHERE raw_id = ?
            """,
            (raw_id,),
        )
        row = cursor.fetchone()
    finally:
        conn.close()

    if row is None:
        raise KeyError(f"No RawEvent found with raw_id={raw_id!r}")

    return RawEvent(
        raw_id=row[0],
        source_id=row[1],
        timestamp_ingested=row[2],
        format_guess=row[3],
        raw_text=row[4],
    )
