# services/pipeline/tests/test_worker.py — run-loop resilience (controller R16b).
#
# A batch that blows up anywhere (here: the unguarded rules SELECT surfacing a
# transient DB drop) must degrade to retry-next-batch: run() logs and keeps
# consuming — never process death, never an offset commit for the failed batch
# (§10: Postgres down -> workers stop committing offsets -> replay on recovery).
# No Kafka, no real DB: the conn is a stub whose every cursor() raises.
import pytest

from pipeline.worker import PipelineWorker


class InterruptingConsumer:
    """First consume() returns one batch; the second raises to stop the loop
    (the same way main() shuts down — KeyboardInterrupt)."""

    def __init__(self, batch):
        self._batch = batch
        self.calls = 0

    def subscribe(self, topic):
        pass

    def consume(self, num_messages, timeout):
        self.calls += 1
        if self.calls == 1:
            return self._batch
        raise KeyboardInterrupt

    def commit(self):
        raise AssertionError("offsets must never be committed for a failed batch")

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
    # raises out of process_batch. run() must absorb that, log it, and come
    # back around for the next batch (R16b: degrade to retry, not death).
    msgs = [FakeMsg(0, 7, b"not-json")]
    worker = PipelineWorker(InterruptingConsumer(msgs), SilentProducer(), BrokenConn())
    with caplog.at_level("ERROR", logger="pipeline.worker"), pytest.raises(KeyboardInterrupt):
        worker.run()  # must reach consume #2, i.e. survive batch 1
    assert worker.consumer.calls == 2
    assert "offsets NOT committed" in caplog.text
