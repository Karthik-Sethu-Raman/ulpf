"""Value mutation for the candidate probe and the fragmentation bench (spec §9, §6.2).

Single definition of the mutation machinery, ported verbatim from
bench/fingerprint_fragmentation.py (M1) — which now imports this module
instead of carrying its own copy. One switch differs from the bench's
historical entry point: ``vary_text``. The bench additionally replaces runs
of free-text words to prove message wording never changes shape; the
candidate validation probe (ulpf_core.validation) must NOT vary free words,
because a rule pattern may legitimately pin one (e.g. an iptables ``DROP``
keyword), so it mutates values only.

Timestamps mutate first and park behind \\x00 sentinels so later numeric
passes cannot chew freshly generated values into shape-breaking forms.
IP:port mutates before the IP pass so the ":port" tail does not lose the
digit its lookbehind needs.
"""

from __future__ import annotations

import random
import re
from collections.abc import Callable

from ulpf_core.fingerprint import _classify

_ISO_TS_RE = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}):(\d{2}))?([+-]\d{2}:?\d{2}|Z)?"
)
_SYSLOG_TS_RE = re.compile(
    r"\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec))"
    r"\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\b"
)
_PORT_RE = re.compile(r"(?<=\d):\d{1,5}\b")              # port tail of IP:port
_IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_KV_NUM_RE = re.compile(r"(?<==)\d{1,5}\b")               # key=12345 values
_JSON_NUM_RE = re.compile(r'(?<=":)\d{1,5}\b')            # "key":12345 values
_HOSTNAME_RE = re.compile(r"\b[a-z][a-z0-9-]*\d{1,4}\b")  # fw01, vpn-gw01, eth0
_SENTINEL_RE = re.compile(r"\x00A(\d+)\x00")
_MONTH_RE = re.compile(r"^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$")
_MARKUP_CHARS = set('{}"<>')

WORDS = [
    "alpha", "bravo", "delta", "echo", "fox", "golf",
    "hotel", "india", "juliet", "kilo", "lima", "mike",
]


def _rand_iso_ts(match: re.Match[str], rng: random.Random) -> str:
    text = f"{rng.randint(2020, 2030):04d}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"
    if match.group(4):
        text += f"T{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}"
    return text + (match.group(7) or "")


def _rand_syslog_ts(match: re.Match[str], rng: random.Random) -> str:
    # Keep the month word so the mutant still detects as syslog.
    return (
        f"{match.group(1)} {rng.randint(1, 28)} "
        f"{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}"
    )


def _rand_ip(rng: random.Random) -> str:
    return ".".join(str(rng.randint(1, 254)) for _ in range(4))


def mutate_line(line: str, rng: random.Random, *, vary_text: bool = False) -> str:
    """Return a same-shape mutant of *line*: replaces an IPv4, a port, a
    timestamp, a hostname token (``h\\d+``/``fw\\d+`` style) or a run of
    digits — values change, shape must not.

    With ``vary_text=True`` (the bench) the free-text pass also randomizes
    runs of free-text words; the probe (default) leaves free words alone.
    """
    stash: list[str] = []

    def _swap(make: Callable[[re.Match[str]], str]) -> Callable[[re.Match[str]], str]:
        def _sub(match: re.Match[str]) -> str:
            stash.append(make(match))
            return f"\x00A{len(stash) - 1}\x00"

        return _sub

    line = _ISO_TS_RE.sub(_swap(lambda m: _rand_iso_ts(m, rng)), line)
    line = _SYSLOG_TS_RE.sub(_swap(lambda m: _rand_syslog_ts(m, rng)), line)
    line = _PORT_RE.sub(_swap(lambda m: f":{rng.randint(1, 65535)}"), line)
    line = _IP_RE.sub(_swap(lambda m: _rand_ip(rng)), line)
    line = _KV_NUM_RE.sub(_swap(lambda m: str(rng.randint(1, 65535))), line)
    line = _JSON_NUM_RE.sub(_swap(lambda m: str(rng.randint(1, 65535))), line)
    line = _HOSTNAME_RE.sub(_swap(lambda m: f"h{rng.randint(0, 9999):04d}"), line)

    # Free-text runs (message bodies) get a random word count. Structural
    # tokens (markup, sentinels, syslog month, anything classified) are kept.
    if vary_text and " " in line:
        kept: list[str] = []
        run: list[str] = []

        def _flush() -> None:
            if run:
                kept.extend(rng.choice(WORDS) for _ in range(rng.randint(1, 6)))
                run.clear()

        for token in line.split():
            if (
                _SENTINEL_RE.fullmatch(token)
                or _MONTH_RE.fullmatch(token)
                or _MARKUP_CHARS.intersection(token)
                or _classify(token) != "W"
            ):
                _flush()
                kept.append(token)
            else:
                run.append(token)
        _flush()
        line = " ".join(kept)

    return _SENTINEL_RE.sub(lambda m: stash[int(m.group(1))], line)
