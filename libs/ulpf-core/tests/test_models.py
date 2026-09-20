import pytest
from pydantic import ValidationError
from ulpf_core.models import RawEnvelope


def test_envelope_roundtrip():
    e = RawEnvelope(source_id="fw01", transport="syslog-udp",
                    received_at="2026-09-19T10:00:00+00:00", raw="Aug 27 14:32:07 fw01 kernel: X")
    assert RawEnvelope.model_validate_json(e.model_dump_json()) == e

def test_envelope_rejects_empty_and_oversized():
    with pytest.raises(ValidationError):
        RawEnvelope(source_id="s", transport="http", received_at="t", raw="")
    with pytest.raises(ValidationError):
        RawEnvelope(source_id="s", transport="http", received_at="t", raw="x" * 70000)


def test_envelope_format_hint_capped_at_64():
    ok = RawEnvelope(source_id="s", transport="http", received_at="t",
                     raw="x", format_hint="f" * 64)
    assert ok.format_hint == "f" * 64
    with pytest.raises(ValidationError):
        RawEnvelope(source_id="s", transport="http", received_at="t",
                    raw="x", format_hint="f" * 65)


def test_event_envelope_contract_shape():
    # R17 topic contract (normalized.events): M3's drift service imports this
    # model, so the exact field set and defaults are frozen here.
    from ulpf_core.models import EventEnvelope

    env = EventEnvelope(event_id="e", raw_id="r", fingerprint_id="auto_x",
                        rule_version=2, status="parsed", ocsf={"severity_id": 5})
    assert env.model_dump() == {"event_id": "e", "raw_id": "r",
                                "fingerprint_id": "auto_x", "rule_version": 2,
                                "status": "parsed", "ocsf": {"severity_id": 5}}
    unparsed = EventEnvelope(event_id="e", raw_id="r", fingerprint_id="f",
                             rule_version=0, status="unparsed")
    assert unparsed.ocsf is None
