"""Per-line format fingerprinting and shape hashing (spec §9, M1 version).

Two layers, both deterministic and cheap (no model calls):

- ``fingerprint_id(line)``: known-format ids (``cef_<vendor>``, ``leef_<vendor>``,
  ``json``, ``syslog``, ``csv``, ``xml``) ported from the battle-tested
  legacy-demo/parser_engine/fingerprint.py heuristics, plus new csv/xml branches.
  Anything else gets a provisional ``auto_<8hex>`` id derived from its shape
  hash, so unknown vendors never share an "unknown" bucket (spec §9).

- ``shape_sequence(line)`` / ``shape_hash(line)``: a coarse structural class
  per token. Two events of the same format must hash identically even when
  IPs, ports, timestamps, hostnames and message wording differ — that is the
  fragmentation guarantee the bench (bench/fingerprint_fragmentation.py)
  measures. Tunings that make this hold:
    * numeric collapse — every pure number is the same class (``N``);
    * empty key=value values (``OUT=``, ``FLAGS=``) classify like word values,
      so present-but-empty fields match present-with-value fields;
    * runs of free-text tokens (``W``) collapse to a single ``W`` so message
      word count does not change the shape.

M1 scope: per-line assignment only; sessionization comes later.
"""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET

# --- Known-format detection (ported from legacy-demo/parser_engine/fingerprint.py) ---

# Standard 3-letter syslog month abbreviations
SYSLOG_MONTH_RE = re.compile(
    r"^<?\d*>?\s*(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
    re.IGNORECASE,
)
SYSLOG_PRI_RE = re.compile(r"^<\d{1,3}>")

_XML_TAG_RE = re.compile(r"<[^>]*>")


def _is_csv(text: str) -> bool:
    """CSV heuristic: at least 2 commas and no whitespace outside quotes."""
    if text.count(",") < 2:
        return False
    in_quotes = False
    for ch in text:
        if ch == '"':
            in_quotes = not in_quotes
        elif not in_quotes and ch.isspace():
            return False
    return True


def _first_element_end(text: str) -> int | None:
    """Index just past the first complete top-level XML element, or None."""
    depth = 0
    for match in _XML_TAG_RE.finditer(text):
        body = match.group(0)[1:-1]
        if body.startswith(("!", "?")):  # <?xml ...?>, <!DOCTYPE ...>
            continue
        if body.startswith("/"):
            depth -= 1
            if depth == 0:
                return match.end()
        elif body.endswith("/"):  # self-closing
            if depth == 0:
                return match.end()
        else:
            depth += 1
    return None


def _is_xml(text: str) -> bool:
    """XML heuristic: parses as XML, or its truncated first element does.

    RecursionError is caught alongside ParseError: a deeply-nested hostile
    line can exhaust the parser's recursion before it yields a ParseError
    (recursion-limited ElementTree builds), and an escaped RecursionError
    would wedge the consuming pipeline batch in a redelivery loop. Either
    failure classifies as "not xml" and falls through to the shape hash.
    """
    try:
        ET.fromstring(text)
        return True
    except (ET.ParseError, RecursionError):
        pass
    end = _first_element_end(text)
    if end is None:
        return False
    try:
        ET.fromstring(text[:end])
        return True
    except (ET.ParseError, RecursionError):
        return False


def _known_format(line: str) -> str | None:
    """Return the known-format id for this line, or None if unknown."""
    text = line.strip()
    if not text:
        return None

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

    # 5. XML before CSV: compact single-line XML (<a>1,2</a><b>3,4</b>) has no
    # whitespace and can carry commas, so the csv heuristic would misread it.
    if text.startswith("<") and _is_xml(text):
        return "xml"

    # 6. CSV Format
    if _is_csv(text):
        return "csv"

    return None


# --- Shape classification ---

_IP = r"\d{1,3}(?:\.\d{1,3}){3}"

_SHAPE_RULES = [
    (re.compile(rf"{_IP}:\d+$"), "IPPORT"),
    (re.compile(rf"{_IP}$"), "IP"),
    (re.compile(r"^[0-9a-fA-F:]{6,}$"), "HEXISH"),     # MAC / IPv6-ish
    (re.compile(r"^\d{4}-\d{2}-\d{2}[T ].+"), "ISOTS"),
    (re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}$"), "SYSLOGTS"),
    (re.compile(r"^\d+$"), "N"),                        # numeric collapse
]


def _classify(token: str) -> str:
    # Iterative over nested key=value layers ("a=b=c" -> "KV:KV:<class>"): the
    # recursive form drove one stack frame per "=" and a hostile single token
    # with thousands of layers wedged the pipeline batch with RecursionError
    # (same failure class as _is_xml's RecursionError guard).
    prefixes: list[str] = []
    while "=" in token:
        # An empty value ("OUT=", "FLAGS=") classifies like a word value so a
        # field that is present-but-empty hashes the same as one with a value.
        _, _, token = token.partition("=")
        prefixes.append("KV:")
    for rx, name in _SHAPE_RULES:
        if rx.match(token):
            return "".join(prefixes) + name
    return "".join(prefixes) + "W"


def shape_sequence(line: str) -> list[str]:
    """Structural class per token; free-text runs collapse to a single W."""
    text = line.strip()
    tokens = text.split() if " " in text else re.split(r"[|;,]", text)
    sequence: list[str] = []
    for cls in (_classify(token) for token in tokens):
        # Message bodies vary in word count between events of the same format,
        # so a run of free-text tokens hashes as one W (spec §9 stability).
        if cls == "W" and sequence and sequence[-1] == "W":
            continue
        sequence.append(cls)
    return sequence


def shape_hash(line: str) -> str:
    return hashlib.sha256("|".join(shape_sequence(line)).encode()).hexdigest()[:8]


def fingerprint_id(line: str) -> str:
    known = _known_format(line)          # returns e.g. "cef_paloalto" or None
    return known if known else f"auto_{shape_hash(line)}"
