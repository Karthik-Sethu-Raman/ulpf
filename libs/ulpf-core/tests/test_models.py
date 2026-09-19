import pytest
from ulpf_core.models import RawEnvelope

def test_envelope_roundtrip():
    e = RawEnvelope(source_id="fw01", transport="syslog-udp",
                    received_at="2026-09-19T10:00:00+00:00", raw="Aug 27 14:32:07 fw01 kernel: X")
    assert RawEnvelope.model_validate_json(e.model_dump_json()) == e

def test_envelope_rejects_empty_and_oversized():
    with pytest.raises(Exception):
        RawEnvelope(source_id="s", transport="http", received_at="t", raw="")
    with pytest.raises(Exception):
        RawEnvelope(source_id="s", transport="http", received_at="t", raw="x" * 70000)
