# services/pipeline/tests/test_quarantine.py — R-M3-6 (spec §7.2): the worker
# filters mappings whose OCSF path the drift role quarantined (Task 5 appends
# to rules.quarantined_fields) BEFORE parse; the captured key then lands in
# doc['unmapped'] — "mapping disabled, values preserved". An empty quarantine
# list is the M1/M2 hot path and MUST stay byte-identical: pinned here
# against an explicit expected document and a no-quarantine baseline run.
# No Kafka, no real DB (test_worker house style: fakes + monkeypatched
# persistence; the loader pin lives in test_rules.py).
import json

from ulpf_core.fingerprint import fingerprint_id
from ulpf_core.ids import event_id_for, raw_id_for
from ulpf_core.models import Mapping

import pipeline.worker as worker_mod
from pipeline.rules import ActiveRule
from pipeline.worker import PipelineWorker

# Real corpus line (simulator/data/raw_logs_syslog.txt) — both this and the
# nomatch line below fingerprint to the known-format id "syslog", so they hit
# the same active rule.
IPTABLES_LINE = ("Aug 27 14:32:07 fw01 kernel: IPTABLES-DROP: IN=eth0 OUT= "
                 "SRC=203.0.113.45 DST=192.168.1.10 LEN=60 PROTO=TCP "
                 "SPT=51422 DPT=22 FLAGS=SYN")
NOMATCH_SYSLOG_LINE = "Aug 27 14:35:00 fw01 sshd[1234]: Accepted publickey for root"

# The seed's syslog pattern: extension KV scan, SRC/DST mapped (M2 shape).
PATTERN = r"^.*?IPTABLES-\w+:\s*(?P<extension>.*)$"

# What the line parses to with NO quarantine — the explicit M2 regression
# pin. OUT= is never captured by the extension KV grammar (empty value with
# no terminator), so it is absent from unmapped: asserted as the code
# behaves. time is the worker's received_at fill (no time mapping).
EXPECTED_DOC = {
    "class_uid": 4001,
    "class_name": "Network Activity",
    "activity_id": 99,
    "severity_id": None,
    "time": "2026-09-19T12:00:00+00:00",
    "src_endpoint": {"ip": "203.0.113.45"},
    "dst_endpoint": {"ip": "192.168.1.10"},
    "action": None,
    "message": None,
    "metadata": {"product": "ULPF"},
    "unmapped": {"IN": "eth0", "LEN": 60, "PROTO": "TCP",
                 "SPT": 51422, "DPT": 22, "FLAGS": "SYN"},
}


def syslog_rule(quarantined=None):
    """ActiveRule for the syslog fingerprint; quarantined=None means the kwarg
    is not passed at all — the exact M2 construction path."""
    kwargs: dict = {
        "id": 11,
        "fingerprint_id": fingerprint_id(IPTABLES_LINE),
        "version": 2,
        "pattern": PATTERN,
        "mappings": [Mapping(source_field="SRC", ocsf_path="src_endpoint.ip"),
                     Mapping(source_field="DST", ocsf_path="dst_endpoint.ip")],
        "provenance": "human",
    }
    if quarantined is not None:
        kwargs["quarantined_fields"] = quarantined
    return ActiveRule(**kwargs)


def envelope_bytes(raw):
    return json.dumps({"source_id": "s", "transport": "udp",
                       "received_at": "2026-09-19T12:00:00+00:00",
                       "raw": raw}).encode()


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


class StubConn:
    """Only rollback() is reachable: persistence is monkeypatched out and
    every message's fingerprint has an active rule (no sample-count query)."""

    def rollback(self):
        pass


class SilentProducer:
    def produce(self, *args, **kwargs):
        pass

    def flush(self, timeout=10.0):
        return 0


class CommitCounter:
    def __init__(self):
        self.commits = 0

    def commit(self):
        self.commits += 1


def run_batch(monkeypatch, rule, lines):
    """One process_batch of *lines* under *rule* (all lines share the rule's
    fingerprint — asserted); returns the NormalizedRows persist_normalized
    received, in message order."""
    assert {fingerprint_id(line) for line in lines} == {rule.fingerprint_id}
    seen: dict = {}
    monkeypatch.setattr(worker_mod, "persist_batch", lambda conn, rows, parts: None)
    monkeypatch.setattr(worker_mod, "load_active_rules",
                        lambda conn: {rule.fingerprint_id: rule})
    monkeypatch.setattr(worker_mod, "persist_normalized",
                        lambda conn, events, samples=None: seen.update(events=events))
    msgs = [FakeMsg(0, i + 1, envelope_bytes(line)) for i, line in enumerate(lines)]
    worker = PipelineWorker(CommitCounter(), SilentProducer(), StubConn())
    assert worker.process_batch(msgs) is True
    return seen["events"]


def test_quarantined_mapping_skipped_value_in_unmapped(monkeypatch):
    events = run_batch(monkeypatch, syslog_rule(["src_endpoint.ip"]), [IPTABLES_LINE])
    row = events[0]
    assert row.status == "parsed"
    doc = row.ocsf
    # src_endpoint's ONLY mapping was the quarantined one: _new_parts starts
    # it as {} and _build_document renders an empty endpoint as None — that
    # is what the code produces (mapping disabled, spec §7.2).
    assert doc["src_endpoint"] is None
    assert doc["dst_endpoint"] == {"ip": "192.168.1.10"}  # untouched mapping
    # The value is preserved verbatim in unmapped (never dropped, §6.4/§7.2):
    # everything else is exactly the no-quarantine document.
    assert doc["unmapped"] == dict(EXPECTED_DOC["unmapped"], SRC="203.0.113.45")
    assert {k: v for k, v in doc.items() if k not in ("src_endpoint", "unmapped")} == {
        k: v for k, v in EXPECTED_DOC.items() if k not in ("src_endpoint", "unmapped")}


def test_empty_quarantine_identical_behavior(monkeypatch):
    # REGRESSION PIN: quarantined_fields=[] must be byte-identical to the M2
    # no-quarantine path (the worker's falsy check short-circuits the
    # model_copy — zero object churn): same document, pinned explicitly
    # below, and identical event_id / rule_id / rule_version.
    baseline = run_batch(monkeypatch, syslog_rule(), [IPTABLES_LINE])[0]
    empty_q = run_batch(monkeypatch, syslog_rule([]), [IPTABLES_LINE])[0]

    assert empty_q.status == baseline.status == "parsed"
    assert empty_q.ocsf == EXPECTED_DOC
    assert empty_q.ocsf == baseline.ocsf
    assert empty_q.event_id == baseline.event_id == event_id_for(
        raw_id_for("raw.logs", 0, 1), 2)
    assert (empty_q.rule_id, empty_q.rule_version) == \
        (baseline.rule_id, baseline.rule_version) == (11, 2)


def test_model_copy_preserves_id(monkeypatch):
    # The filter's model_copy must preserve the ActiveRule subclass: rule.id
    # attribution and rule.version ride along on the filtered rule for parsed
    # AND parse_error rows alike — the MAX_LINE_CHARS cap and the parse-error
    # path read the same loop-local rule the copy produced.
    parsed, error = run_batch(
        monkeypatch, syslog_rule(["src_endpoint.ip"]),
        [IPTABLES_LINE, NOMATCH_SYSLOG_LINE])

    assert parsed.status == "parsed"
    assert parsed.rule_id == 11 and parsed.rule_version == 2  # id survived the copy
    assert error.status == "parse_error"
    assert error.rule_id == 11 and error.rule_version == 2
    assert error.event_id == event_id_for(raw_id_for("raw.logs", 0, 2), 2)
    assert error.ocsf is None
