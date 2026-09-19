# libs/ocsf-schema/tests/test_validator.py
import sys

from ocsf_schema.validator import validate_document


def _valid_doc() -> dict:
    return {
        "class_uid": 4001,
        "class_name": "Network Activity",
        "activity_id": 99,
        "severity_id": None,
        "time": None,
        "src_endpoint": {"ip": "203.0.113.45", "port": 51422},
        "dst_endpoint": {"ip": "192.168.1.10", "port": 443},
        "action": "block",
        "message": "Suspicious DNS Query",
        "metadata": {"product": "ULPF"},
        "unmapped": {"cat": "spyware"},
    }


def test_valid_document_passes():
    assert validate_document(_valid_doc()) == []


def test_null_time_and_string_time_both_legal():
    # time is nullable: parse() runs pre-pipeline, where ingestion time is not
    # filled yet; a mapped ISO timestamp is the other legal shape.
    doc = _valid_doc()
    doc["time"] = "2026-08-27T14:32:07Z"
    assert validate_document(doc) == []
    doc["time"] = None
    assert validate_document(doc) == []


def test_severity_int_and_null_both_legal():
    doc = _valid_doc()
    doc["severity_id"] = 5
    assert validate_document(doc) == []
    doc["severity_id"] = None
    assert validate_document(doc) == []


def test_missing_required_field_rejected():
    doc = _valid_doc()
    del doc["unmapped"]
    assert validate_document(doc)


def test_unknown_class_uid_rejected():
    doc = _valid_doc()
    doc["class_uid"] = 4002
    assert validate_document(doc)


def test_activity_id_out_of_range_rejected():
    doc = _valid_doc()
    doc["activity_id"] = 100
    assert validate_document(doc)


def test_undeclared_property_rejected():
    doc = _valid_doc()
    doc["evil_path"] = {"password": "hunter2"}  # root additionalProperties: false
    assert validate_document(doc)


def test_metadata_wrong_product_rejected():
    doc = _valid_doc()
    doc["metadata"] = {"product": "NotULPF"}
    assert validate_document(doc)


def test_port_must_be_integer_or_string():
    doc = _valid_doc()
    doc["src_endpoint"]["port"] = [51422]  # neither integer nor string
    assert validate_document(doc)
    doc["src_endpoint"]["port"] = "51422"  # string is legal per schema
    assert validate_document(doc) == []


def test_jsonschema_missing_falls_back_to_no_errors(monkeypatch):
    # Contract: jsonschema optional at runtime — ImportError degrades to [].
    # (None in sys.modules makes `from jsonschema import ...` raise ImportError.)
    monkeypatch.setitem(sys.modules, "jsonschema", None)
    assert validate_document(_valid_doc()) == []
