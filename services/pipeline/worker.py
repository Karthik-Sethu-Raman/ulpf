# services/pipeline/worker.py — the sole raw.logs consumer (M1 walking skeleton).
#
# Per batch of up to 500 messages (or 2s), the spec-critical ordering (§4):
#   1. build_rows (fingerprint at build time, controller R3)
#   2. persist_batch  — raw_events + raw_batches chain, COMMITTED
#   3. refresh active rules
#   4. per event: apply active rule or 'unparsed'; parse failures -> parse_error
#      + pipeline.dlq; parsed docs -> normalized.events (key=fingerprint_id)
#   5. persist_normalized — COMMITTED
#   6. only then consumer.commit()
# Crash/rollback anywhere before step 6 and the worker seeks each affected
# partition back to the failed batch's first offset (consume() had already
# advanced the position; the next no-arg commit() would otherwise cover the
# failed batch and its events would be silently lost). Redelivery is a no-op
# on the DB side: every write is deterministic and ON CONFLICT-guarded (§4).
#
# parsed_at is the raw event's received_at (not wall clock) so a replay mints
# the same event_id and collides instead of duplicating. M1 never supersedes
# (superseded_by_event_id stays NULL, controller R9).
import json
import logging
import os

from ocsf_schema.validator import validate_document
from ulpf_core.ids import event_id_for
from ulpf_core.parsing import parse

from pipeline.db import NormalizedRow, build_rows, persist_batch, persist_normalized
from pipeline.rules import load_active_rules

log = logging.getLogger("pipeline.worker")

TOPIC_RAW = "raw.logs"
TOPIC_NORMALIZED = "normalized.events"
TOPIC_DLQ = "pipeline.dlq"
GROUP_ID = "pipeline"  # exact name: Task 12's forced-replay deletes this group (controller R3b)

BATCH_SIZE = 500
BATCH_TIMEOUT_S = 2.0
MAX_LINE_CHARS = 65536  # spec §10 line cap — re-checked before parse (collector checks at ingest)
CANARY_EVERY = 100      # every 100th parsed doc through validate_document (spec §6.4)

# Sentinel rule version for events no active rule matched: deterministic, so a
# replay of the same raw line yields the same event_id and is skipped.
UNPARSED_RULE_VERSION = 0


class KafkaConsumer:
    """confluent_kafka.Consumer wrapper; import deferred so this module (and
    the unit tests) load without librdkafka on the host (controller R14)."""

    def __init__(self, bootstrap: str, group_id: str = GROUP_ID):
        import confluent_kafka  # deferred: unit tests never need librdkafka

        self._consumer = confluent_kafka.Consumer({
            "bootstrap.servers": bootstrap,
            "group.id": group_id,
            "auto.offset.reset": "earliest",  # raw-first: never silently skip history
            "enable.auto.commit": False,      # offsets only after both DB txns
        })

    def subscribe(self, topic: str) -> None:
        self._consumer.subscribe([topic])

    def consume(self, num_messages: int, timeout: float) -> list:
        return self._consumer.consume(num_messages=num_messages, timeout=timeout)

    def seek(self, partition_offsets: dict[int, int]) -> None:
        """Seek each partition back to *offset* (failed-batch redelivery).

        confluent_kafka keeps the import deferred here, like __init__."""
        import confluent_kafka

        for partition, offset in sorted(partition_offsets.items()):
            self._consumer.seek(
                confluent_kafka.TopicPartition(TOPIC_RAW, partition, offset))

    def commit(self) -> None:
        self._consumer.commit()

    def close(self) -> None:
        self._consumer.close()


class KafkaProducer:
    """confluent_kafka.Producer wrapper for normalized.events / pipeline.dlq."""

    def __init__(self, bootstrap: str):
        import confluent_kafka  # deferred: unit tests never need librdkafka

        self._producer = confluent_kafka.Producer({"bootstrap.servers": bootstrap})

    def produce(self, topic: str, key: str, value: dict) -> None:
        self._producer.produce(topic, key=key.encode(), value=json.dumps(value).encode())
        self._producer.poll(0)  # serve delivery callbacks without blocking

    def flush(self, timeout: float = 10.0) -> int:
        return self._producer.flush(timeout)


class PipelineWorker:
    """Wires consumer + producer + DB connection into the batch loop.

    Collaborators are injected (tests and main() pass fakes or real wrappers);
    nothing here imports psycopg or confluent_kafka at module import time.
    """

    def __init__(self, consumer, producer, conn):
        self.consumer = consumer
        self.producer = producer
        self.conn = conn
        self.canary_failures = 0  # spec §6.4: canary failures logged + counted
        self._parsed_total = 0

    def _seek_back(self, msgs) -> None:
        """Seek every partition in *msgs* back to its first failed-batch offset.

        consume() advances the consumer position past a batch regardless of
        processing success, and no-arg commit() commits that position — so a
        failed batch whose offsets were merely 'not committed' would be
        silently covered by the next successful batch's commit. Seeking back
        makes the failed batch the next thing consumed (at-least-once, §4).
        """
        first: dict[int, int] = {}
        for msg in msgs:
            partition, offset = msg.partition(), msg.offset()
            if partition not in first or offset < first[partition]:
                first[partition] = offset
        try:
            self.consumer.seek(first)
        except Exception:
            # Never let a seek failure kill the loop; the next failed batch
            # re-attempts the seek, and rebalances reset positions to the
            # (clean) committed offsets anyway.
            log.exception("seek-back failed; offsets NOT committed; will re-seek on next failure")

    def run(self) -> None:
        self.consumer.subscribe(TOPIC_RAW)
        log.info("pipeline consuming %s as group %r", TOPIC_RAW, GROUP_ID)
        while True:
            msgs = self.consumer.consume(num_messages=BATCH_SIZE, timeout=BATCH_TIMEOUT_S)
            data = []
            for msg in msgs:
                if msg.error() is not None:  # broker/codec event, not a data message
                    log.warning("consumer event (non-data): %s", msg.error())
                    continue
                data.append(msg)
            if data:
                # The WHOLE iteration is guarded (R16): a transient DB/Kafka
                # drop anywhere in the batch must degrade to redelivery of
                # THAT batch (seek back + offsets stay uncommitted), not
                # process death and not silent position advance.
                try:
                    self.process_batch(data)
                except Exception:
                    self._seek_back(data)
                    log.exception("batch failed; seeked back to first failed offsets; "
                                  "offsets NOT committed; batch redelivered")

    def process_batch(self, msgs) -> bool:
        """One full batch; returns True iff offsets were committed.

        Any persist failure aborts the batch BEFORE the offset commit: the
        transaction is rolled back and Kafka redelivers (at-least-once).
        """
        rows, partitions = build_rows(msgs)

        # Raw first: raw rows + chain are durable before any parsing (spec §4).
        try:
            persist_batch(self.conn, rows, partitions)
        except Exception:
            self.conn.rollback()
            self._seek_back(msgs)  # redeliver THIS batch, not just hope for it
            log.exception("raw persist failed; seeked back to first failed offsets; "
                          "offsets NOT committed; batch redelivered")
            return False

        rules = load_active_rules(self.conn)  # refreshed every batch
        events: list[NormalizedRow] = []
        parsed = unparsed = parse_errors = 0
        for row in rows:
            rule = rules.get(row.fingerprint_id)
            if rule is None:
                events.append(NormalizedRow(
                    event_id=event_id_for(row.raw_id, UNPARSED_RULE_VERSION),
                    raw_id=row.raw_id,
                    raw_received_at=row.received_at,
                    parsed_at=row.received_at,  # := raw received_at (deterministic, spec §4)
                    fingerprint_id=row.fingerprint_id,
                    rule_id=None,
                    rule_version=UNPARSED_RULE_VERSION,
                    status="unparsed",
                    ocsf=None,
                ))
                unparsed += 1
                continue

            # Line cap re-checked here: parse() runs untrusted text on the hot path.
            if len(row.raw_text) > MAX_LINE_CHARS:
                events.append(self._parse_error_row(
                    row, rule, f"line exceeds {MAX_LINE_CHARS} char cap"))
                parse_errors += 1
                continue

            doc, err = parse(row.raw_text, rule)
            if err is not None:
                events.append(self._parse_error_row(row, rule, err))
                parse_errors += 1
                continue

            # parse() leaves time None when the rule maps no timestamp; the
            # pipeline fills ingestion time before emission (ulpf_core.parsing).
            if doc["time"] is None:
                doc["time"] = row.received_at.isoformat()

            self._parsed_total += 1
            if self._parsed_total % CANARY_EVERY == 0:  # canary, never per-event (spec §6.4)
                problems = validate_document(doc)
                if problems:
                    self.canary_failures += 1
                    log.error("canary doc invalid for %s: %s", row.fingerprint_id, problems)

            events.append(NormalizedRow(
                event_id=event_id_for(row.raw_id, rule.version),
                raw_id=row.raw_id,
                raw_received_at=row.received_at,
                parsed_at=row.received_at,
                fingerprint_id=row.fingerprint_id,
                rule_id=rule.id,
                rule_version=rule.version,
                status="parsed",
                ocsf=doc,
            ))
            try:
                self.producer.produce(TOPIC_NORMALIZED, row.fingerprint_id, doc)
            except Exception:
                # The normalized row is durable in step 5 regardless; a lost
                # emission is visible via the DB and must not stall the batch.
                log.exception("produce to %s failed for %s", TOPIC_NORMALIZED, row.raw_id)
            parsed += 1

        try:
            persist_normalized(self.conn, events)
        except Exception:
            self.conn.rollback()
            self._seek_back(msgs)  # redeliver THIS batch (raw rows ON CONFLICT dedup)
            log.exception("normalized persist failed; seeked back to first failed offsets; "
                          "offsets NOT committed; batch redelivered")
            return False

        # Both DB txns durable -> safe to advance. commit() (no args) commits
        # the consumer POSITION, which already covers every consumed batch —
        # any batch that failed earlier must have seeked back above, or this
        # commit would silently cover it.
        self.consumer.commit()
        log.info("batch: %d consumed, %d parsed, %d unparsed, %d parse_error, "
                 "%d skipped-envelope, canary_failures=%d",
                 len(msgs), parsed, unparsed, parse_errors, len(msgs) - len(rows),
                 self.canary_failures)
        return True

    def _parse_error_row(self, row, rule, error: str) -> NormalizedRow:
        """DLQ produce + the parse_error row, which joins the same normalized
        txn as the rest of the batch."""
        try:
            self.producer.produce(TOPIC_DLQ, row.fingerprint_id, {
                "raw_id": str(row.raw_id),
                "fingerprint_id": row.fingerprint_id,
                "error": error,
            })
        except Exception:
            # Same reasoning as normalized.events: the DB row below is the
            # record of truth; a lost DLQ emission must not stall the batch.
            log.exception("produce to %s failed for %s", TOPIC_DLQ, row.raw_id)
        return NormalizedRow(
            event_id=event_id_for(row.raw_id, rule.version),
            raw_id=row.raw_id,
            raw_received_at=row.received_at,
            parsed_at=row.received_at,
            fingerprint_id=row.fingerprint_id,
            rule_id=rule.id,
            rule_version=rule.version,
            status="parse_error",
            ocsf=None,
        )


def connect_db(url: str):
    """psycopg connection for pipeline_role (INSERT+SELECT only, no UPDATE/DELETE)."""
    import psycopg  # deferred: unit tests never need psycopg

    return psycopg.connect(url)


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    bootstrap = os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092")
    db_url = os.environ.get(
        "DATABASE_URL", "postgresql://pipeline_role:pipeline_dev@localhost:5432/ulpf"
    )
    consumer = KafkaConsumer(bootstrap)
    producer = KafkaProducer(bootstrap)
    conn = connect_db(db_url)
    worker = PipelineWorker(consumer, producer, conn)
    try:
        worker.run()
    except KeyboardInterrupt:
        log.info("shutdown requested")
    finally:
        consumer.close()
        remaining = producer.flush(10)
        if remaining:
            log.error("shutdown flush: %d message(s) still queued", remaining)
        conn.close()


if __name__ == "__main__":
    main()
