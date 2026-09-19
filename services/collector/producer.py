# services/collector/producer.py — thin wrapper over confluent_kafka.Producer.
# Produces RawEnvelope JSON to raw.logs, keyed by source_id. No parsing happens here.
import json
import logging

log = logging.getLogger("collector.producer")

TOPIC = "raw.logs"


class KafkaProducer:
    """confluent_kafka.Producer wrapper: produce_raw(env) + flush() on shutdown.

    confluent_kafka is imported lazily so this module stays importable in test
    environments without librdkafka (tests inject a fake producer instead).
    """

    def __init__(self, bootstrap: str):
        import confluent_kafka  # deferred: keeps the module importable without librdkafka

        self._producer = confluent_kafka.Producer({"bootstrap.servers": bootstrap})

    def produce_raw(self, env: dict) -> None:
        self._producer.produce(
            TOPIC,
            key=env["source_id"].encode(),
            value=json.dumps(env).encode(),
        )
        self._producer.poll(0)  # serve delivery callbacks without blocking

    def flush(self, timeout: float = 10.0) -> int:
        """Flush on shutdown; returns the number of messages still queued."""
        remaining = self._producer.flush(timeout)
        if remaining:
            log.error("flush timeout: %d message(s) still queued", remaining)
        return remaining
