# bench/onboarding_eval/test_sanity_eval.py — unit tests for the sanity-eval's
# PURE layer: table formatting, rate cells, corpus-path resolution, doc header,
# and the per-corpus aggregation driven by a canned (offline) SLM client. The
# harness itself is a manual tool (no pytest run against a live Ollama).
import time

import pytest
import sanity_eval
from onboarding.generate import GenerationError

# ---------- format_table ----------

def test_format_table_aligns_columns():
    table = sanity_eval.format_table(
        ["corpus", "runs", "held_out_match"],
        [["acmegw", "3", "80.0%"], ["zenwall", "3", "100.0%"]],
    )
    lines = table.splitlines()
    assert lines[0] == "| corpus  | runs | held_out_match |"
    assert lines[1] == "| ------- | ---- | -------------- |"
    assert lines[2] == "| acmegw  | 3    | 80.0%          |"
    assert lines[3] == "| zenwall | 3    | 100.0%         |"


def test_format_table_empty_rows_still_renders_header():
    assert sanity_eval.format_table(["a", "bb"], []) == "| a | bb |\n| - | -- |"


# ---------- cell helpers ----------

def test_pct():
    assert sanity_eval.pct(1.0) == "100.0%"
    assert sanity_eval.pct(0.855) == "85.5%"
    assert sanity_eval.pct(0.0) == "0.0%"
    assert sanity_eval.pct(None) == "n/a"  # no responses observed (all runs failed)


def test_num():
    assert sanity_eval.num(2.0) == "2.0"
    assert sanity_eval.num(1.333333) == "1.3"
    assert sanity_eval.num(None) == "n/a"


# ---------- corpus resolution ----------

def test_find_corpora_prefers_first_dir_with_the_file(tmp_path):
    golden = tmp_path / "golden"
    sim = tmp_path / "sim"
    golden.mkdir()
    sim.mkdir()
    (golden / "raw_logs_acmegw.txt").write_text("x\n", encoding="utf-8")
    (sim / "raw_logs_newapp.txt").write_text("y\n", encoding="utf-8")

    found = sanity_eval.find_corpora(["acmegw", "zenwall", "newapp"], [golden, sim])
    assert found["acmegw"] == golden / "raw_logs_acmegw.txt"
    assert found["newapp"] == sim / "raw_logs_newapp.txt"
    assert found["zenwall"] is None  # missing corpus stays visible, not fatal


# ---------- aggregation over runs (offline fake SLM) ----------

class FakeClient:
    """Canned SLMClient: pops one prepared response per chat() call."""

    def __init__(self, *responses):
        self.responses = list(responses)

    def chat(self, prompt, temperature):
        return self.responses.pop(0)


GOOD_RULE = """{
  "pattern": "^.*? (?P<extension>src=.*)$",
  "field_mappings": [
    {"source_field": "src", "ocsf_path": "src_endpoint.ip"},
    {"source_field": "dst", "ocsf_path": "dst_endpoint.ip"}
  ]
}"""

LINES = [
    f"host=h{i:02d} src=10.0.0.{i} dst=10.0.1.{i} "
    f"sport={1000 + i} dport={80 + i} action=allow msg=flow ok"
    for i in range(20)
]


def test_evaluate_corpus_success_run_metrics():
    # One clean attempt per run: response is valid JSON whose pattern compiles.
    factory = lambda: FakeClient(GOOD_RULE)
    result = sanity_eval.evaluate_corpus(
        "fake", LINES, client_factory=factory, runs=2)
    assert result["corpus"] == "fake"
    assert result["runs"] == 2
    assert result["rules_stored"] == 2
    assert result["responses"] == 2
    assert result["valid_json"] == 2
    assert result["compiles"] == 2
    assert result["mean_attempts"] == 1.0
    assert result["held_out_match_rate"] == 1.0
    assert result["sec_per_rule"] >= 0.0


def test_evaluate_corpus_counts_failed_attempts():
    bad = "not json at all"
    factory = lambda: FakeClient(bad, bad, GOOD_RULE)
    result = sanity_eval.evaluate_corpus(
        "fake", LINES, client_factory=factory, runs=1)
    assert result["responses"] == 3
    assert result["valid_json"] == 1
    assert result["mean_attempts"] == 3.0
    assert result["rules_stored"] == 1


# ---------- doc assembly ----------

def test_build_doc_carries_header_notes_and_table():
    results = [{
        "corpus": "fake", "runs": 2, "rules_stored": 2, "responses": 2,
        "valid_json": 2, "compiles": 2, "mean_attempts": 1.0,
        "held_out_match_rate": 1.0, "sec_per_rule": 0.5,
    }]
    doc = sanity_eval.build_doc(
        results, model="fake-model", host_cpu="test-cpu",
        date_str="2026-09-20", runs=2)
    assert "- model: fake-model" in doc
    assert "- host CPU: test-cpu" in doc
    assert "- date: 2026-09-20" in doc
    assert "- runs per corpus: 2" in doc
    assert "| corpus" in doc and "| fake " in doc


def test_build_doc_notes_chat_timeout_only_when_set():
    results = [{
        "corpus": "fake", "runs": 1, "rules_stored": 1, "responses": 1,
        "valid_json": 1, "compiles": 1, "mean_attempts": 1.0,
        "held_out_match_rate": 1.0, "sec_per_rule": 0.5,
    }]
    doc = sanity_eval.build_doc(results, model="m", host_cpu="c",
                                date_str="2026-09-21", runs=1,
                                chat_timeout=1200.0)
    assert "- per-chat timeout: 1200s" in doc
    plain = sanity_eval.build_doc(results, model="m", host_cpu="c",
                                  date_str="2026-09-21", runs=1)
    assert "timeout" not in plain


# ---------- --chat-timeout bound (eval-side; the production loop is unbounded) ----------

class SlowClient:
    """chat() that sleeps past any sane test bound — stands in for a
    degenerate SLM answer that would otherwise run for hours."""

    def __init__(self, delay, result="ok"):
        self.delay = delay
        self.result = result

    def chat(self, prompt, temperature):
        time.sleep(self.delay)
        return self.result


def test_timeout_client_returns_fast_answers_unchanged():
    client = sanity_eval.TimeoutClient(FakeClient(GOOD_RULE), timeout_s=5.0)
    assert client.chat("p", 0.1) == GOOD_RULE


def test_timeout_client_bounds_a_runaway_chat():
    client = sanity_eval.TimeoutClient(SlowClient(1.0), timeout_s=0.05)
    start = time.monotonic()
    with pytest.raises(sanity_eval.ChatTimeout):
        client.chat("p", 0.1)
    assert time.monotonic() - start < 0.5  # bounded well below the inner 1.0s


def test_timeout_client_relays_transport_errors():
    class Boom:
        def chat(self, prompt, temperature):
            raise ConnectionError("down")

    client = sanity_eval.TimeoutClient(Boom(), timeout_s=5.0)
    with pytest.raises(ConnectionError):
        client.chat("p", 0.1)


def test_chat_timeout_rides_the_production_retry_ladder():
    # ChatTimeout must be an ordinary chat() failure for generate_candidate:
    # retried at escalating temperature, then GenerationError -> the eval
    # records an honest failed-run row instead of hanging overnight.
    calls = []

    class AlwaysSlow:
        def chat(self, prompt, temperature):
            calls.append(temperature)
            raise sanity_eval.ChatTimeout("no response within 1s")

    with pytest.raises(GenerationError):
        sanity_eval.generate_candidate("fp", LINES, AlwaysSlow())
    assert [round(t, 1) for t in calls] == [0.1, 0.3, 0.5]
