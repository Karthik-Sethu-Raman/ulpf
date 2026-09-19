# services/pipeline/db.py — idempotent raw-first persistence + chain append.
#
# persist_batch() is the system's correctness core, one transaction per batch:
#   staging COPY -> INSERT .. ON CONFLICT (raw_id, received_at) DO NOTHING
#   -> per-partition raw_batches append (prev_hash -> prior merkle_root).
# Raw rows land BEFORE any parsing happens (raw-first, spec §4); a forced
# replay re-runs the same statements, the ON CONFLICT dedups raw_events while
# raw_batches honestly records the re-delivery (Task 12 Assert D).
#
# psycopg is imported lazily inside the persist functions only, so unit tests
# exercise build_rows()/the dataclasses without psycopg installed (mirrors the
# collector's deferred confluent_kafka import). persist_* commit on success and
# leave the transaction aborted on failure — the worker rolls back and does NOT
# commit offsets, so failed batches are redelivered (at-least-once).
from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from ulpf_core.fingerprint import fingerprint_id
from ulpf_core.ids import raw_id_for
from ulpf_core.models import RawEnvelope

from pipeline.hashchain import GENESIS_PREV_HASH, merkle_root

if TYPE_CHECKING:
    import psycopg

log = logging.getLogger("pipeline.db")

_RAW_COLUMNS = (
    "raw_id", "received_at", "source_id", "transport", "format_hint",
    "fingerprint_id", "content_hash", "raw_text",
)


@dataclass(frozen=True)
class RawRow:
    """One raw_events row; field order matches _RAW_COLUMNS for the COPY."""

    raw_id: uuid.UUID
    received_at: datetime
    source_id: str
    transport: str
    format_hint: str | None
    fingerprint_id: str
    content_hash: str
    raw_text: str


@dataclass
class PartitionMeta:
    """Per-Kafka-partition grouping of one consume batch (offsets in order)."""

    partition_id: int
    first_offset: int
    last_offset: int
    content_hashes: list[str]


@dataclass(frozen=True)
class NormalizedRow:
    """One normalized_events row. superseded_by_event_id stays NULL: M1 never
    supersedes (single active rule version per fingerprint, controller R9)."""

    event_id: uuid.UUID
    raw_id: uuid.UUID
    raw_received_at: datetime
    parsed_at: datetime
    fingerprint_id: str
    rule_id: int | None
    rule_version: int | None
    status: str
    ocsf: dict | None


def build_rows(msgs) -> tuple[list[RawRow], dict[int, PartitionMeta]]:
    """Assemble RawRows + per-partition PartitionMeta from Kafka messages.

    Pure logic: each message's JSON value is validated against RawEnvelope,
    the fingerprint is classified at build time (controller R3 — pipeline_role
    cannot UPDATE post-insert, so fingerprint_id must be set before the COPY),
    and content_hash is sha256 of the raw line's UTF-8 bytes. Undecodable or
    invalid envelopes are logged and skipped (the offset still advances past
    them — a poison envelope must not wedge the group). Same message twice
    yields identical rows: deterministic idempotency precondition.
    """
    rows: list[RawRow] = []
    parts: dict[int, PartitionMeta] = {}
    for msg in msgs:
        topic, partition, offset = msg.topic(), msg.partition(), msg.offset()
        try:
            env = RawEnvelope(**json.loads(msg.value()))
        except (ValueError, TypeError) as exc:
            log.warning("skipping %s[%d@%d]: undecodable/invalid envelope: %s",
                        topic, partition, offset, exc)
            continue
        raw_text = env.raw
        meta = parts.get(partition)
        if meta is None:
            meta = parts[partition] = PartitionMeta(partition, offset, offset, [])
        meta.last_offset = offset
        row = RawRow(
            raw_id=raw_id_for(topic, partition, offset),
            received_at=datetime.fromisoformat(env.received_at),
            source_id=env.source_id,
            transport=env.transport,
            format_hint=env.format_hint,
            fingerprint_id=fingerprint_id(raw_text),
            content_hash=hashlib.sha256(raw_text.encode()).hexdigest(),
            raw_text=raw_text,
        )
        rows.append(row)
        meta.content_hashes.append(row.content_hash)
    return rows, parts


def persist_batch(conn: psycopg.Connection, rows: list[RawRow],
                  partitions: dict[int, PartitionMeta]) -> None:
    """Insert raw rows idempotently + append the per-partition chain, ONE txn.

    staging COPY -> INSERT .. ON CONFLICT (raw_id, received_at) DO NOTHING ->
    per-partition raw_batches append with batch_seq = COALESCE(MAX, 0)+1 (safe:
    one consumer per partition, spec §4), prev_hash = prior batch's merkle_root
    (GENESIS_PREV_HASH for the first), row_hashes = the batch's ordered
    content_hash list, and merkle_root computed from exactly that list.
    Commits on success; on failure the caller rolls back and skips the offset
    commit so Kafka redelivers the batch.
    """
    if not partitions:
        return
    from psycopg.types.json import Json  # deferred: keeps psycopg off the test path

    with conn.cursor() as cur:
        cur.execute("CREATE TEMP TABLE staging_raw (LIKE raw_events INCLUDING DEFAULTS) ON COMMIT DROP")
        with cur.copy(
            f"COPY staging_raw ({', '.join(_RAW_COLUMNS)}) FROM STDIN"
        ) as copy:
            for row in rows:
                copy.write_row(dataclasses.astuple(row))
        cur.execute(
            f"INSERT INTO raw_events ({', '.join(_RAW_COLUMNS)}) "
            f"SELECT {', '.join(_RAW_COLUMNS)} FROM staging_raw "
            "ON CONFLICT (raw_id, received_at) DO NOTHING"
        )
        for partition_id in sorted(partitions):
            meta = partitions[partition_id]
            cur.execute(
                "SELECT COALESCE(MAX(batch_seq), 0) + 1 FROM raw_batches WHERE partition_id = %s",
                (partition_id,),
            )
            batch_seq = cur.fetchone()[0]
            cur.execute(
                "SELECT merkle_root FROM raw_batches WHERE partition_id = %s "
                "ORDER BY batch_seq DESC LIMIT 1",
                (partition_id,),
            )
            prev = cur.fetchone()
            prev_hash = prev[0] if prev else GENESIS_PREV_HASH
            cur.execute(
                "INSERT INTO raw_batches (partition_id, batch_seq, prev_hash, merkle_root, "
                "row_hashes, count, first_offset, last_offset) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    partition_id, batch_seq, prev_hash, merkle_root(meta.content_hashes),
                    Json(meta.content_hashes), len(meta.content_hashes),
                    meta.first_offset, meta.last_offset,
                ),
            )
    conn.commit()
    log.info("raw batch persisted: %d row(s) across %d partition(s)", len(rows), len(partitions))


def persist_normalized(conn: psycopg.Connection, events: list[NormalizedRow]) -> None:
    """Insert normalized rows idempotently (staged ON CONFLICT on
    (event_id, parsed_at)), ONE txn; commits on success.

    The FK to raw_events holds because persist_batch already committed the raw
    rows; a replay collides on the PK and is skipped (spec §4 idempotency).
    """
    if not events:
        return
    from psycopg.types.json import Json  # deferred: keeps psycopg off the test path

    columns = (
        "event_id", "raw_id", "raw_received_at", "parsed_at", "fingerprint_id",
        "rule_id", "rule_version", "status", "ocsf",
    )
    with conn.cursor() as cur:
        cur.execute("CREATE TEMP TABLE staging_ne (LIKE normalized_events INCLUDING DEFAULTS) ON COMMIT DROP")
        with cur.copy(f"COPY staging_ne ({', '.join(columns)}) FROM STDIN") as copy:
            for ev in events:
                copy.write_row((
                    ev.event_id, ev.raw_id, ev.raw_received_at, ev.parsed_at,
                    ev.fingerprint_id, ev.rule_id, ev.rule_version, ev.status,
                    Json(ev.ocsf) if ev.ocsf is not None else None,
                ))
        cur.execute(
            f"INSERT INTO normalized_events ({', '.join(columns)}) "
            f"SELECT {', '.join(columns)} FROM staging_ne "
            "ON CONFLICT (event_id, parsed_at) DO NOTHING"
        )
    conn.commit()
    log.info("normalized batch persisted: %d row(s)", len(events))
