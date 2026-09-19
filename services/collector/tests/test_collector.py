# services/collector/tests/test_collector.py — collector unit tests (fake producer, no Kafka).
import pytest
from collector.app import build_app   # FastAPI app factory; producer injected

class FakeProducer:
    def __init__(self): self.produced = []
    def produce_raw(self, env_dict): self.produced.append(env_dict)

@pytest.fixture
def client():
    prod = FakeProducer()
    app = build_app(producer=prod, udp=False)   # UDP disabled in tests
    from fastapi.testclient import TestClient
    return TestClient(app), prod

def test_http_ingest_builds_envelopes(client):
    c, prod = client
    r = c.post("/v1/ingest", json={"source_id": "ids01", "lines": ['{"a":1}', '{"a":2}']})
    assert r.status_code == 202 and r.json() == {"accepted": 2}
    assert len(prod.produced) == 2
    env = prod.produced[0]
    assert env["source_id"] == "ids01" and env["transport"] == "http" and env["raw"] == '{"a":1}'
    assert env["received_at"]  # ISO8601 present

def test_http_rejects_oversized_line(client):
    c, prod = client
    r = c.post("/v1/ingest", json={"source_id": "x", "lines": ["y" * 70000]})
    assert r.status_code == 422

def test_syslog_handler_wraps_datagram():
    from collector.app import make_envelope
    env = make_envelope("syslog-udp", "fw01", "Aug 27 14:32:07 fw01 kernel: X")
    assert env["transport"] == "syslog-udp" and env["source_id"] == "fw01"

def test_source_id_derived_from_peer_address():
    # R7: UDP/TCP syslog source_id comes from the peer address, not a static name.
    from collector.app import source_id_for
    assert source_id_for("syslog-udp", ("10.1.2.3", 1234)) == "udp-10.1.2.3"
    assert source_id_for("syslog-tcp", ("10.1.2.4", 5555)) == "tcp-10.1.2.4"
