# services/pipeline/tests/test_batch_builder.py — build_rows() pure batch assembly.
# No DB, no Kafka: fakes duck-type the confluent_kafka Message interface
# (topic()/partition()/offset()/value()); psycopg is never imported (db.py
# keeps it lazy), so this runs on any host with ulpf-core installed.
import hashlib
import json

from ulpf_core.fingerprint import fingerprint_id
from ulpf_core.ids import raw_id_for

from pipeline.db import build_rows

TOPIC = "raw.logs"


class FakeMsg:
    """Duck-typed confluent_kafka.Message carrying one RawEnvelope JSON value."""

    def __init__(self, partition: int, offset: int, envelope: dict):
        self._partition = partition
        self._offset = offset
        self._value = json.dumps(envelope).encode()

    def topic(self):
        return TOPIC

    def partition(self):
        return self._partition

    def offset(self):
        return self._offset

    def value(self):
        return self._value


def envelope(raw='{"a":1}', source_id="ids01", transport="http",
             received_at="2026-09-19T12:00:00+00:00", **extra):
    env = {"source_id": source_id, "transport": transport,
           "received_at": received_at, "raw": raw}
    env.update(extra)
    return env


def test_build_rows_maps_raw_fields():
    raw = "CEF:0|acme|gw|1|probe|deny|high|src=198.51.100.7"
    rows, parts = build_rows([FakeMsg(2, 41, envelope(raw=raw))])
    row = rows[0]
    assert row.raw_id == raw_id_for(TOPIC, 2, 41)
    assert row.received_at.isoformat() == "2026-09-19T12:00:00+00:00"
    assert row.source_id == "ids01" and row.transport == "http"
    assert row.format_hint is None
    assert row.raw_text == raw
    assert row.content_hash == hashlib.sha256(raw.encode()).hexdigest()
    # R3: fingerprint classified at raw-insert time, before the batch COPY.
    assert row.fingerprint_id == fingerprint_id(raw)
    meta = parts[2]
    assert meta.partition_id == 2
    assert meta.first_offset == 41 and meta.last_offset == 41
    assert meta.content_hashes == [row.content_hash]


def test_partitions_grouped_in_message_order():
    msgs = [
        FakeMsg(0, 7, envelope()),
        FakeMsg(1, 3, envelope()),
        FakeMsg(0, 8, envelope(raw='{"b":2}')),
    ]
    rows, parts = build_rows(msgs)
    assert [r.raw_id for r in rows] == [
        raw_id_for(TOPIC, 0, 7), raw_id_for(TOPIC, 1, 3), raw_id_for(TOPIC, 0, 8),
    ]
    assert parts[0].first_offset == 7 and parts[0].last_offset == 8
    assert len(parts[0].content_hashes) == 2
    assert parts[1].first_offset == 3 and parts[1].last_offset == 3
    assert len(parts[1].content_hashes) == 1


def test_same_message_twice_identical_rows():
    # Idempotency precondition: replay yields byte-identical rows + metas,
    # so the ON CONFLICT insert and the chain append see the same values.
    msg = FakeMsg(1, 9, envelope())
    rows1, parts1 = build_rows([msg])
    rows2, parts2 = build_rows([FakeMsg(1, 9, envelope())])
    assert rows1 == rows2
    assert parts1 == parts2


def test_malformed_envelope_skipped_not_fatal():
    bad = FakeMsg(0, 1, {"source_id": "x"})  # missing transport/received_at/raw
    good = FakeMsg(0, 2, envelope())
    rows, parts = build_rows([bad, good])
    assert len(rows) == 1
    assert rows[0].raw_id == raw_id_for(TOPIC, 0, 2)
    assert parts[0].first_offset == 2  # poison offset simply advances past


def test_oversized_line_skipped():
    # RawEnvelope's 65536-char cap (spec §10) applies at build time too.
    big = FakeMsg(0, 5, envelope(raw="x" * 70000))
    rows, parts = build_rows([big])
    assert rows == [] and parts == {}
