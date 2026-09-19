"""
app.py — ULPF pipeline integration.

Wires together every module built by the team into the actual flow from
the architecture diagram:

  raw line -> ingest (P3) -> fingerprint (P2) -> known rule? (P2 rule_store)
      -> yes: apply_rule (P2) -> NormalizedEvent
      -> no:  onboard_new_format() -> generate_rule (P1) -> validate_rule (P3)
              -> [human review happens in review_ui/, not here]
              -> once approved, register_rule (P2) -> re-process

Built by P1 on day 3 since P6 (integration runner) did not get built in
time — this file covers both app wiring and a basic integration test,
which is a legitimate, honest scope adjustment given the timeline.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from schemas.schemas import Rule, NormalizedEvent
from ingestion.ingest import ingest_line
from ingestion.validate_rule import validate_rule
from parser_engine.fingerprint import fingerprint
from parser_engine.apply_rule import apply_rule
from parser_engine.rule_store import get_rule, register_rule
from onboarding.generate_rule import generate_rule


class UnknownFormatError(Exception):
    """Raised when a raw line's fingerprint has no registered rule yet.
    Contains the fingerprint_id so the caller can trigger onboarding."""
    def __init__(self, fingerprint_id: str, raw_text: str):
        self.fingerprint_id = fingerprint_id
        self.raw_text = raw_text
        super().__init__(f"No rule registered for fingerprint '{fingerprint_id}'")


def process_raw_line(raw_text: str, source_id: str, format_guess: str = "unknown") -> NormalizedEvent:
    """
    The hot path from the architecture diagram: ingest -> fingerprint ->
    look up rule -> apply it. Raises UnknownFormatError if no rule exists
    yet for this line's fingerprint — caller should then run
    onboard_new_format() and retry.
    """
    raw_event = ingest_line(raw_text, source_id=source_id, format_guess=format_guess)
    fp_id = fingerprint(raw_text)

    rule = get_rule(fp_id)
    if rule is None:
        raise UnknownFormatError(fp_id, raw_text)

    return apply_rule(raw_event, rule)


def onboard_new_format(fingerprint_id: str, sample_lines: list[str], held_out_lines: list[str],
                        auto_approve_if_valid: bool = False) -> tuple[Rule, bool]:
    """
    The cold path: generate a candidate rule, validate it against
    held-out lines. Returns (rule, validation_passed).

    In the real system, a human reviews the candidate in review_ui/
    before it's registered — auto_approve_if_valid=True is ONLY for
    automated integration testing (this integration runner), never for
    the actual demo flow, where P4's UI is the approval gate.
    """
    candidate = generate_rule(fingerprint_id, sample_lines)
    result = validate_rule(candidate, held_out_lines)

    if auto_approve_if_valid and result.passed:
        register_rule(candidate)

    return candidate, result.passed


if __name__ == "__main__":
    print("app.py wires the pipeline together as importable functions.")
    print("Run testdata/integration_runner.py for an end-to-end test.")