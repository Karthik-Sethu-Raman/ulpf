from pydantic import BaseModel, Field


class RawEnvelope(BaseModel):
    source_id: str
    transport: str                      # "syslog-udp" | "syslog-tcp" | "http"
    received_at: str                    # ISO8601 UTC, set by collector
    raw: str = Field(min_length=1, max_length=65536)  # line cap, spec §10
    format_hint: str | None = Field(default=None, max_length=64)

class EventEnvelope(BaseModel):
    """R17 topic contract (normalized.events, key=fingerprint_id): ONE envelope
    per event — parsed, unparsed or parse_error — with the parsed OCSF document
    present only for status='parsed'. M3's drift service imports this model, so
    field names and types are a frozen cross-service contract."""

    event_id: str
    raw_id: str
    fingerprint_id: str
    rule_version: int
    status: str                         # "parsed" | "unparsed" | "parse_error"
    ocsf: dict | None = None

class Mapping(BaseModel):
    source_field: str
    ocsf_path: str

class Rule(BaseModel):
    fingerprint_id: str
    version: int
    pattern: str
    mappings: list[Mapping]
    provenance: str                     # "slm" | "slm-edited" | "human"
