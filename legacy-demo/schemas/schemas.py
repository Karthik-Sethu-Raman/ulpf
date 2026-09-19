"""
ULPF canonical data contracts.

DO NOT MODIFY without agreement from the whole team. Every module is built
and tested against these exact shapes. Import from this file — do not
redefine these types locally inside your own module.

If your module needs a field that isn't here, flag it in the team chat
before adding it — a silent schema change breaks everyone else's code.
"""

from dataclasses import dataclass, field
from typing import Optional, Literal


@dataclass
class RawEvent:
    raw_id: str               # unique id assigned at ingestion, e.g. "raw_00042"
    source_id: str            # device identifier, e.g. "fw01", "vpn-gw01"
    timestamp_ingested: str   # ISO8601 — when WE received it, not the event's own time
    format_guess: str         # "syslog" | "cef" | "leef" | "json" | "csv" | "unknown"
    raw_text: str              # the exact original log line, byte-for-byte untouched


@dataclass
class FieldMapping:
    source_field: str         # name/position in the raw log, e.g. "src" or "token_3"
    ocsf_path: str             # dotted OCSF field path, e.g. "src_endpoint.ip"


@dataclass
class Rule:
    fingerprint_id: str        # which structural family this rule applies to
    pattern: str                 # regex with named capture groups, e.g. (?P<src>...)
    field_mappings: list[FieldMapping]
    confidence: float             # 0.0-1.0, from generation step
    provenance: Literal["slm-generated", "slm-generated-edited", "human-authored"]
    version: int                   # starts at 1, incremented on re-onboarding
    created_at: str                 # ISO8601


@dataclass
class ValidationResult:
    rule_fingerprint_id: str
    passed: bool
    checks: dict[str, bool]   # e.g. {"ip_fields_look_like_ips": True, "required_fields_populated": False}
    notes: str


@dataclass
class NormalizedEvent:
    event_id: str
    raw_id: str                 # link back to RawEvent.raw_id — THIS is the traceability requirement
    fingerprint_id: str
    rule_version: int
    class_name: str              # OCSF class, e.g. "Network Activity"
    time: str                     # ISO8601 — the EVENT's own time, parsed from the log
    severity_id: Optional[int] = None
    src_endpoint: Optional[dict] = None    # {"ip": ..., "port": ...}
    dst_endpoint: Optional[dict] = None
    action: Optional[str] = None
    unmapped_fields: dict = field(default_factory=dict)  # never silently drop data — put it here


@dataclass
class DriftMetric:
    fingerprint_id: str
    field_name: str
    window_start: str
    window_end: str
    null_rate: float
    baseline_null_rate: float
    severity: Literal["none", "minor", "moderate", "severe"]
