# services/pipeline/tests/test_worker.py — run-loop resilience (controller
# R16b) + failed-batch seek-back (final-review critical).
#
# A batch that blows up anywhere must degrade to redelivery of THAT batch:
# run() logs and keeps consuming — never process death, never an offset commit
# for the failed batch. Because consume() advances the consumer position
# regardless of processing success and no-arg commit() commits that position,
# a failed batch must be seeked back to its first failed offsets, or a later
# successful batch would silently cover it (lossless guarantee, spec §10).
# No Kafka, no real DB: fakes duck-type the consumer; the conn is a stub.
import json

import pytest

import pipeline.worker as worker_mod
from pipeline.worker import PipelineWorker


def envelope_bytes(raw="x"):
    return json.dumps({"source_id": "s", "transport": "udp",
                       "received_at": "2026-09-19T12:00:00+00:00",
                       "raw": raw}).encode()


class RecordingConsumer:
    """First consume() returns one batch; the second raises to stop the loop
    (the same way main() shuts down — KeyboardInterrupt). Records every
    seek() and flags any commit() via the assertion in commit itself."""

    def __init__(self, batch):
        self._batch = batch
        self.calls = 0
        self.seeks: list[dict] = []
        self.commits = 0

    def subscribe(self, topic):
        pass

    def consume(self, num_messages, timeout):
        self.calls += 1
        if self.calls == 1:
            return self._batch
        raise KeyboardInterrupt

    def seek(self, partition_offsets):
        self.seeks.append(dict(partition_offsets))

    def commit(self):
        self.commits += 1

    def close(self):
        pass


class BrokenConn:
    """Stands in for a transiently-down Postgres: every cursor() raises."""

    def rollback(self):
        pass

    def cursor(self):
        raise RuntimeError("db down")


class SilentProducer:
    def produce(self, *args, **kwargs):
        pass

    def flush(self, timeout=10.0):
        return 0


class FakeMsg:
    def __init__(self, partition, offset, value: bytes):
        self._p, self._o, self._v = partition, offset, value

    def topic(self):
        return "raw.logs"

    def partition(self):
        return self._p

    def offset(self):
        return self._o

    def error(self):
        return None

    def value(self):
        return self._v


def test_run_survives_batch_crash_and_keeps_consuming(caplog):
    # Undecodable value -> build_rows skips it -> persist_batch is a no-op ->
    # the unguarded rules SELECT (load_active_rules) hits the broken conn and
    # raises out of process_batch. run() must absorb that, seek the batch's
    # partitions back to their first failed offsets, and come back around for
    # the next batch (R16b: degrade to redelivery, not death).
    msgs = [FakeMsg(0, 7, b"not-json")]
    worker = PipelineWorker(RecordingConsumer(msgs), SilentProducer(), BrokenConn())
    with caplog.at_level("ERROR", logger="pipeline.worker"), pytest.raises(KeyboardInterrupt):
        worker.run()  # must reach consume #2, i.e. survive batch 1
    assert worker.consumer.calls == 2
    assert worker.consumer.seeks == [{0: 7}]  # failed batch is the next thing consumed
    assert worker.consumer.commits == 0
    assert "offsets NOT committed" in caplog.text


def test_persist_batch_failure_seeks_back_to_first_failed_offsets(monkeypatch):
    # CRITICAL (lossless guarantee): on a raw-persist failure every partition
    # of the failed batch must be seeked back to its FIRST offset, and no
    # offset commit may happen on that path — otherwise the next successful
    # batch's commit would cover the failed one and its events would be gone.
    def boom(conn, rows, partitions):
        raise RuntimeError("transient db drop")

    monkeypatch.setattr(worker_mod, "persist_batch", boom)
    msgs = [FakeMsg(0, 7, envelope_bytes()), FakeMsg(0, 8, envelope_bytes()),
            FakeMsg(2, 41, envelope_bytes())]
    consumer = RecordingConsumer(msgs)
    worker = PipelineWorker(consumer, SilentProducer(), BrokenConn())
    assert worker.process_batch(msgs) is False
    assert consumer.seeks == [{0: 7, 2: 41}]
    assert consumer.commits == 0


def test_persist_normalized_failure_seeks_back_and_never_commits(monkeypatch):
    # Same contract on the normalized-persist failure path: the raw rows of
    # this batch may already be durable, but offsets stay uncommitted and the
    # partitions seek back so the batch is redelivered (raw ON CONFLICT dedups).
    monkeypatch.setattr(worker_mod, "persist_batch", lambda conn, rows, parts: None)
    monkeypatch.setattr(worker_mod, "load_active_rules", lambda conn: {})

    def boom(conn, events, samples=None):
        raise RuntimeError("transient db drop")

    monkeypatch.setattr(worker_mod, "persist_normalized", boom)

    class RollbackOnlyConn:
        def rollback(self):
            pass

        class _Cur:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def execute(self, sql, params=None):
                pass

            def fetchall(self):
                return []

        def cursor(self):
            return self._Cur()  # sample-count query finds no existing samples

    msgs = [FakeMsg(0, 7, envelope_bytes()), FakeMsg(2, 41, envelope_bytes())]
    consumer = RecordingConsumer(msgs)
    worker = PipelineWorker(consumer, SilentProducer(), RollbackOnlyConn())
    assert worker.process_batch(msgs) is False
    assert consumer.seeks == [{0: 7, 2: 41}]


def test_every_event_produced_as_envelope_keyed_by_fingerprint(monkeypatch):
    # R17: the pipeline ships ONE envelope per event — parsed, unparsed AND
    # parse_error — to normalized.events, keyed by fingerprint_id, shaped
    # exactly like ulpf_core.models.EventEnvelope (M3's drift service imports
    # it). The fake producer round-trips value through json.dumps/loads, so a
    # non-JSON-safe field (e.g. a raw UUID) fails right here.
    from ulpf_core.fingerprint import fingerprint_id
    from ulpf_core.ids import event_id_for, raw_id_for
    from ulpf_core.models import EventEnvelope, Mapping

    from pipeline.rules import ActiveRule

    monkeypatch.setattr(worker_mod, "persist_batch", lambda conn, rows, parts: None)

    seen: dict = {}
    monkeypatch.setattr(
        worker_mod, "persist_normalized",
        lambda conn, events, samples=None: seen.update(events=events, samples=samples))

    parsed_line = '{"a":1}'
    error_line = "CEF:0|acme|gw|1|probe|nomatch"
    unparsed_line = "some vendor nobody seeded yet"
    fp_parsed, fp_error, fp_unparsed = (
        fingerprint_id(line) for line in (parsed_line, error_line, unparsed_line))
    rules = {
        fp_parsed: ActiveRule(id=1, fingerprint_id=fp_parsed, version=3,
                              pattern="__JSON__",
                              mappings=[Mapping(source_field="a", ocsf_path="message")],
                              provenance="human"),
        fp_error: ActiveRule(id=2, fingerprint_id=fp_error, version=5,
                             pattern="will-not-match-", mappings=[],
                             provenance="human"),
    }
    monkeypatch.setattr(worker_mod, "load_active_rules", lambda conn: rules)

    class CountCursor:
        # The per-batch sample-count SELECT: no existing samples anywhere.
        def __init__(self, calls):
            self._calls = calls

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def execute(self, sql, params=None):
            self._calls.append((sql, params))

        def fetchall(self):
            return []

    class CountConn:
        def __init__(self):
            self.calls: list = []

        def cursor(self):
            return CountCursor(self.calls)

        def rollback(self):
            pass

    class RecordingProducer:
        def __init__(self):
            self.produced: list = []

        def produce(self, topic, key, value):
            self.produced.append((topic, key, json.loads(json.dumps(value))))

    msgs = [FakeMsg(0, 1, envelope_bytes(parsed_line)),
            FakeMsg(0, 2, envelope_bytes(error_line)),
            FakeMsg(1, 9, envelope_bytes(unparsed_line))]
    conn, producer = CountConn(), RecordingProducer()
    worker = PipelineWorker(RecordingConsumer(msgs), producer, conn)
    assert worker.process_batch(msgs) is True

    envelopes = {k: v for t, k, v in producer.produced if t == "normalized.events"}
    assert set(envelopes) == {fp_parsed, fp_error, fp_unparsed}
    # Produced-tuple COUNT per topic (the dict above dedupes by key, which
    # would hide a double-production bug): one envelope per event, and the
    # DLQ carries exactly the one parse_error.
    produced_by_topic: dict[str, int] = {}
    for topic, _, _ in producer.produced:
        produced_by_topic[topic] = produced_by_topic.get(topic, 0) + 1
    assert produced_by_topic == {"normalized.events": 3, "pipeline.dlq": 1}
    expected = {
        fp_parsed: EventEnvelope(
            event_id=str(event_id_for(raw_id_for("raw.logs", 0, 1), 3)),
            raw_id=str(raw_id_for("raw.logs", 0, 1)),
            fingerprint_id=fp_parsed, rule_version=3, status="parsed"),
        fp_error: EventEnvelope(
            event_id=str(event_id_for(raw_id_for("raw.logs", 0, 2), 5)),
            raw_id=str(raw_id_for("raw.logs", 0, 2)),
            fingerprint_id=fp_error, rule_version=5, status="parse_error"),
        fp_unparsed: EventEnvelope(
            event_id=str(event_id_for(raw_id_for("raw.logs", 1, 9), 0)),
            raw_id=str(raw_id_for("raw.logs", 1, 9)),
            fingerprint_id=fp_unparsed, rule_version=0, status="unparsed"),
    }
    for fp, env in expected.items():
        # parsed' ocsf is the full OCSF doc — compared by content below.
        got = {k: v for k, v in envelopes[fp].items() if k != "ocsf"}
        assert got == {k: v for k, v in env.model_dump().items() if k != "ocsf"}
    assert envelopes[fp_parsed]["ocsf"]["message"] == "1"  # parsed doc rides inside
    assert envelopes[fp_error]["ocsf"] is None
    assert envelopes[fp_unparsed]["ocsf"] is None

    # DLQ behavior unchanged: the parse_error still lands there (and only it).
    dlq = [(k, v) for t, k, v in producer.produced if t == "pipeline.dlq"]
    assert len(dlq) == 1 and dlq[0][0] == fp_error

    # Sample capture: ONE grouped count query for the batch's rule-less
    # fingerprints; capture only takes samples for those.
    assert len(conn.calls) == 1
    sql, params = conn.calls[0]
    assert "FROM onboarding_samples" in sql and "count(*)" in sql
    assert params[0] == [fp_unparsed]
    assert [s.fingerprint_id for s in seen["samples"]] == [fp_unparsed]


def test_connect_db_requests_autocommit(monkeypatch):
    # T7: the connection runs autocommit — each persist_* wraps its own
    # `with conn.transaction():` block, so nothing idles inside an open txn.
    import sys
    import types

    seen: dict = {}
    fake_psycopg = types.ModuleType("psycopg")

    def fake_connect(url, **kwargs):
        seen.update(url=url, kwargs=kwargs)
        return object()

    fake_psycopg.connect = fake_connect
    monkeypatch.setitem(sys.modules, "psycopg", fake_psycopg)
    worker_mod.connect_db("postgresql://u:p@h/db")
    assert seen["kwargs"] == {"autocommit": True}
