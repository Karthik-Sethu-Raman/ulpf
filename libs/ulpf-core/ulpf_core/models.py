from pydantic import BaseModel, Field


class RawEnvelope(BaseModel):
    source_id: str
    transport: str                      # "syslog-udp" | "syslog-tcp" | "http"
    received_at: str                    # ISO8601 UTC, set by collector
    raw: str = Field(min_length=1, max_length=65536)  # line cap, spec §10
    format_hint: str | None = None

class Mapping(BaseModel):
    source_field: str
    ocsf_path: str

class Rule(BaseModel):
    fingerprint_id: str
    version: int
    pattern: str
    mappings: list[Mapping]
    provenance: str                     # "slm" | "slm-edited" | "human"
