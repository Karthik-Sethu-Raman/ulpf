# services/onboarding/tests/test_generate.py — SLM prompt/extraction/retry
# semantics (ported from legacy-demo/onboarding/generate_rule.py) + the JSON
# alias fast-path.
#
# The SLM is faked with recording clients (the SLMClient Protocol); the
# `ollama` package is NEVER imported on the test path (OllamaClient defers it
# into .chat()), so this module runs on a host without ollama installed.
import json

import pytest
from ulpf_core.models import Rule
from ulpf_core.parsing import JSON_SENTINEL

from onboarding.generate import (
    GeneratedRule,
    GenerationError,
    build_prompt,
    extract_json,
    generate_candidate,
    generate_json_rule,
)

_SAMPLES = [
    ("LEEF:2.0|Acme|NetGuard|3.2|401|src=198.51.100.7 srcPort=44521 dst=192.168.1.5 "
     "dstPort=443 proto=TCP action=allow msg=Session started"),
    ("LEEF:2.0|Acme|NetGuard|3.2|402|src=203.0.113.9 srcPort=51002 dst=192.168.1.6 "
     "dstPort=22 proto=TCP action=deny msg=Blocked login attempt"),
]

_VALID = json.dumps({
    "pattern": r"^.*\|(?P<extension>.*)$",
    "field_mappings": [
        {"source_field": "src", "ocsf_path": "src_endpoint.ip"},
        {"source_field": "msg", "ocsf_path": "message"},
    ],
})


class FakeSLM:
    """Replays scripted responses; records (prompt, temperature) per call."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[tuple[str, float]] = []

    def chat(self, prompt: str, temperature: float) -> str:
        self.calls.append((prompt, temperature))
        return self.responses.pop(0)


class DownSLM:
    """The SLM host is unreachable: every call raises ConnectionError."""

    def __init__(self):
        self.calls = 0

    def chat(self, prompt: str, temperature: float) -> str:
        self.calls += 1
        raise ConnectionError("ollama unreachable")


class BrokenSLM:
    """A NON-ConnectionError transport failure (httpx.ConnectError and
    ollama.ResponseError are not builtin subclasses) on every call."""

    def __init__(self):
        self.temperatures: list[float] = []

    def chat(self, prompt: str, temperature: float) -> str:
        self.temperatures.append(temperature)
        raise RuntimeError("some other transport boom")


def test_build_prompt_contains_few_shots_and_samples():
    prompt = build_prompt(_SAMPLES)
    assert "LEEF:2.0|Acme|NetGuard" in prompt  # few-shot example 1 (LEEF)
    assert "FW-DROP" in prompt  # few-shot example 2 (iptables prefix)
    assert _SAMPLES[0] in prompt and _SAMPLES[1] in prompt
    assert "src_endpoint.ip" in prompt  # the OCSF target list
    assert "hardcode" in prompt  # anti-hardcoding rule 4


def test_extract_json_strips_fences_and_grabs_outermost_object():
    assert extract_json('```json\n{"pattern": "x"}\n```') == {"pattern": "x"}
    assert extract_json(' Sure! {"a": {"b": 1}} hope that helps ') == {"a": {"b": 1}}
    with pytest.raises(ValueError):
        extract_json("no object here")


def test_generate_candidate_retries_with_error_feedback_and_escalating_temp():
    fake = FakeSLM(["totally not json", _VALID])
    rule = generate_candidate("fp_x", _SAMPLES, fake)

    assert len(fake.calls) == 2  # exactly one retry
    assert [t for _, t in fake.calls] == pytest.approx([0.1, 0.3])
    # Error feedback: the second prompt carries the first attempt's failure.
    assert "failed with error" in fake.calls[1][0]
    assert "totally not json" in fake.calls[1][0]

    assert isinstance(rule, Rule)
    assert isinstance(rule, GeneratedRule)
    assert rule.provenance == "slm"
    assert rule.pattern == r"^.*\|(?P<extension>.*)$"
    assert rule.confidence == 1.0  # every sample matches and all fields resolve


def test_generate_candidate_wraps_connection_error_after_max_attempts():
    fake = DownSLM()
    with pytest.raises(GenerationError):
        generate_candidate("fp_x", _SAMPLES, fake, max_attempts=3)
    assert fake.calls == 3


def test_generate_candidate_retries_any_transport_error_type():
    fake = BrokenSLM()
    with pytest.raises(GenerationError):
        generate_candidate("fp_x", _SAMPLES, fake, max_attempts=3)
    assert fake.temperatures == pytest.approx([0.1, 0.3, 0.5])


def test_generate_candidate_without_lines_raises_generation_error():
    with pytest.raises(GenerationError):
        generate_candidate("fp_x", [], FakeSLM([_VALID]))


def test_generate_json_rule_maps_aliases_and_sets_sentinel():
    lines = [
        ('{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 443, '
         '"dst_port": 80, "msg": "hello"}'),
        ('{"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4", "src_port": 22, '
         '"dst_port": 8080, "msg": "blocked"}'),
    ]
    rule = generate_json_rule("fp_json", lines)

    assert isinstance(rule, Rule)
    assert rule.pattern == JSON_SENTINEL
    assert rule.provenance == "slm"
    assert {m.source_field: m.ocsf_path for m in rule.mappings} == {
        "src_ip": "src_endpoint.ip",
        "dst_ip": "dst_endpoint.ip",
        "src_port": "src_endpoint.port",
        "dst_port": "dst_endpoint.port",
        "msg": "message",
    }
    assert rule.confidence == 1.0


def test_generate_json_rule_requires_parseable_lines():
    with pytest.raises(ValueError):
        generate_json_rule("fp_json", ["not json at all"])


def test_generate_json_rule_rejects_zero_mappings():
    # A JSON format hitting none of the 8 alias entries would yield
    # mappings=[] — every gate check is vacuously true for it, so the rule
    # must be refused instead of stored as a useless pending_review row.
    with pytest.raises(GenerationError, match="no mappable fields via alias table"):
        generate_json_rule("fp_json", ['{"widget": "x"}', '{"widget": "y"}'])
