"""
parser_engine/fingerprint.py

Format fingerprinting for raw security log lines.
Deterministic, cheap, NO AI model calls.
"""

from __future__ import annotations

import json
import re

# Standard 3-letter syslog month abbreviations
SYSLOG_MONTH_RE = re.compile(
    r"^<?\d*>?\s*(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
    re.IGNORECASE,
)
SYSLOG_PRI_RE = re.compile(r"^<\d{1,3}>")


def fingerprint(raw_text: str) -> str:
    """
    Return a fingerprint_id string identifying the structural family of this log line.
    
    Heuristics:
      - "CEF:" header -> extracts vendor/product, e.g. "cef_paloalto"
      - "LEEF:" header -> extracts vendor/product, e.g. "leef_acme"
      - Valid JSON starting with "{" -> "json"
      - Classic Syslog shape (<PRI> or Month DD HH:MM:SS) -> "syslog"
      - Otherwise -> "unknown"
    """
    text = raw_text.strip()
    if not text:
        return "unknown"

    # 1. CEF Header
    if text.startswith("CEF:"):
        parts = text.split("|")
        if len(parts) >= 3:
            vendor = re.sub(r"[^a-zA-Z0-9]", "", parts[1].lower())
            return f"cef_{vendor}" if vendor else "cef"
        return "cef"

    # 2. LEEF Header
    if text.startswith("LEEF:"):
        parts = text.split("|")
        if len(parts) >= 3:
            vendor = re.sub(r"[^a-zA-Z0-9]", "", parts[1].lower())
            return f"leef_{vendor}" if vendor else "leef"
        return "leef"

    # 3. JSON Format
    if text.startswith("{"):
        try:
            json.loads(text)
            return "json"
        except json.JSONDecodeError:
            pass

    # 4. Syslog Format
    if SYSLOG_MONTH_RE.match(text) or SYSLOG_PRI_RE.match(text):
        return "syslog"

    return "unknown"
