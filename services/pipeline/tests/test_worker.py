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

    def boom(conn, events):
        raise RuntimeError("transient db drop")

    monkeypatch.setattr(worker_mod, "persist_normalized", boom)

    class RollbackOnlyConn:
        def rollback(self):
            pass

    msgs = [FakeMsg(0, 7, envelope_bytes()), FakeMsg(2, 41, envelope_bytes())]
    consumer = RecordingConsumer(msgs)
    worker = PipelineWorker(consumer, SilentProducer(), RollbackOnlyConn())
    assert worker.process_batch(msgs) is False
    assert consumer.seeks == [{0: 7, 2: 41}]
