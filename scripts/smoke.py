#!/usr/bin/env python3
"""ULPF acceptance smoke (M1 Task 12 + M2 Task 12 + M3 Task 12, spec §15) —
the milestone exit gate.

End-to-end against the live compose stack: drives the simulator over the golden
corpora, then verifies lossless ingest, the parsed/unparsed split, raw
traceability, forced replay idempotency (consumer-group delete + pipeline
restart), and independently re-verifies EVERY raw_batches merkle root plus the
per-partition hash chain linkage (M1 asserts A-E). The M2 asserts then drive
the onboarding loop end to end: F posts the unknown newapp corpus and takes a
pending_review candidate for its fingerprint through approve -> backlog
re-parse (SLM candidate when the tier produces one, hand-authored manual
fallback otherwise — expected on the default qwen3:4b tier, see
docs/m2-slm-sanity.md), G does the same deterministically for the zenwall
corpus via /api/rules/manual, and H re-runs the replay dance with active
rules, proving raw/normalized/stats/sample-count idempotency including the
onboarding sample dedup. The M3 asserts (I-L) run FIRST, before the A-H block,
and drive the drift engine end to end on the live seeded syslog rule: I proves
tier-1 fires (a fresh drift window with severity >= minor and a nonzero
violation_rate), J that moderate drift quarantines src_endpoint.ip while the
SRC value survives under ocsf.unmapped.SRC (values preserved, mapping
disabled), K that severe drift deactivates the rule (fingerprint re-enters
onboarding — sample_count grows) and a human restores it via reactivate, and
L that a human un-quarantine re-enables the mapping for new parses.

M3 demo env (exported below BEFORE compose up, per the Task 12 brief): the
drift service gets ULPF_DRIFT_WINDOW_COUNT=30 plus a time horizon no demo
gap can cross, so windows close on COUNT ONLY — deterministic 30-row
boundaries (the brief's 15 s time-close is unsound on the accumulating DB:
it slices the days-spread M1/M2 history into one-row windows and arms a
degenerate all-zero baseline before the demo even starts; see the constant
block below). The pipeline additionally gets ULPF_SAMPLE_CAPTURE_CAP=2000:
the accumulating multi-run DB saturates the 200/fingerprint sample cap,
after which a drift-deactivated fingerprint cannot accumulate onboarding
samples and K's re-entry signal (sample_count grows) is unobservable
(observed live in the Task 12 gate).

M3 drift-run tuning (verified live, Task 12): the simulator's firmware-drift
corruption is fully deterministic (selector = (index * 2654435761 % 1000) /
1000 vs an escalating phase), so the smoke REPLICATES that math host-side
(tune_drift_run) and plans the drift simulator run(s) such that the J-window
— the 30-row drift window the quarantine decision rides on — carries a
tier-1 violation_rate in [0.27, 0.43]: moderate (>= 0.20 -> field quarantine,
Assert J) with margin on both sides (severe 0.50 would deactivate first and
skip the quarantine entirely). The quarantine lands at the FIRST scan that
sees that window; when that scan is also the baseline-establishing one the
decision is tier-1-only by construction (the profile arms only after the
scan's windows are recorded), which is what keeps the tier-2 null ladder from
ever preempting J. After the quarantine, every further syslog parse is null
at src_endpoint.ip (mapping disabled), so the next full window hits null_rate
1.0 against the fresh baseline — ratio >= 40x, severe -> rule_deactivated
(Assert K). With a view offset > 0 the plan uses a short PRE-RUN to complete
the establishing window before the main run supplies the J-window's rows.

M3 state restoration (not asserts): severe windows are permanent rows of the
version's current view, and the drift loop re-evaluates the whole view every
scan — so after K's deactivation the reactivated rule would be re-deactivated
by the next scan. The smoke therefore (a) stops the drift container between
K's restore and the end of the M3 block, and (b) finishes with a human
version-bump dance (manual candidate without the SRC mapping -> approve -> the
M2 backlog sweep supersedes every poisoned v1 row at the new version ->
deactivate the new version -> reactivate v1, whose current view is now empty)
before restarting drift. This restores Assert B's seeded-fp precondition for
re-runs on the same accumulating DB (12/12 twice consecutive).

Host requirements (Python 3.13 tested): psycopg[binary] plus the two libs
importable (pip install -e libs/ulpf-core -e libs/ocsf-schema — the smoke
computes fingerprints and validates the hand-authored rules host-side with the
same ulpf_core gate the services run). Everything else is stdlib: urllib for
HTTP, subprocess for docker compose; all Kafka interaction is `docker compose
exec redpanda rpk` (no confluent-kafka host-side).
Docker commands run from deploy/; the DB is NOT reset — every count assertion
is delta-based (snapshot before, diff after), so re-runs accumulate (the M2
asserts snapshot per run too: approved rules from earlier runs persist, later
runs mint the next version and assert deltas).

Usage:  python scripts/smoke.py          (from the repo root)
        ULPF_SMOKE_SLM_WAIT_S=300        (seconds to wait for an SLM candidate
                                          before the hand-authored fallback)
        ULPF_SMOKE_M3_ONLY=1             (DEV: run only the M3 I-L block, skip
                                          the A-H block — the exit gate always
                                          runs the full 12)
Exit:   0 all checks PASS, 1 any FAIL.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import random
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import psycopg

# pipeline.hashchain lives at services/pipeline (package dir named `pipeline`);
# services/ on sys.path is what makes `import pipeline` resolve.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services"))
from pipeline.hashchain import GENESIS_PREV_HASH, merkle_root

# ulpf_core is needed host-side for Asserts F/G: fingerprint_id() names the
# newapp/zenwall fingerprints exactly as the pipeline mints them, and
# validate_candidate() fast-fails the hand-authored fallback rules through the
# SAME deterministic gate the gateway runs server-side.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "libs" / "ulpf-core"))
from ulpf_core.fingerprint import fingerprint_id
from ulpf_core.models import Mapping, Rule
from ulpf_core.validation import validate_candidate

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
DSN = "postgresql://postgres:postgres@localhost:5433/ulpf"  # admin, host port (5433: compose publish; 5432 often owned by a native Postgres)
GATEWAY = "http://localhost:8000"
WEB = "http://localhost:3000"

SIM_EPS = "25"
SIM_DURATION = "20"  # ~500 events: corpora total 56 lines (10+16+15+15) -> several loops
SEEDED_FPS = ("cef_paloalto", "cef_ciscoasa", "cef_fortigate", "syslog", "json")
TRACE_SAMPLE = 20

BUILD_TIMEOUT_S = 900
READY_TIMEOUT_S = 240
SIM_TIMEOUT_S = 300
DRAIN_TIMEOUT_S = 150
LAG_TIMEOUT_S = 180
POLL_INTERVAL_S = 2.0

# M2 (Asserts F/G): R-T12-pre-a — the SLM candidate wait is env-tunable; on
# the default qwen3:4b tier over an 8GB host no candidate ever stores (0.0
# held-out confidence, docs/m2-slm-sanity.md), so the wait expires and the
# hand-authored manual fallback fires. 300s gives a faster tier room to land.
SLM_WAIT_TIMEOUT_S = int(os.environ.get("ULPF_SMOKE_SLM_WAIT_S", "300"))
SAMPLES_WAIT_TIMEOUT_S = 60  # onboarding sample capture for a posted corpus
REPARSE_TIMEOUT_S = 120  # approve -> reparse_complete audit row (R-T12-pre-d)
AUDIT_PAGE = 200  # /api/audit page size (>= any fingerprint's M2-run trail)
M3_ONLY = os.environ.get("ULPF_SMOKE_M3_ONLY", "") == "1"  # dev affordance

COLLECTOR = "http://localhost:8080"
NEWAPP_SOURCE = "newapp01"
ZENWALL_SOURCE = "zenwall01"

NEWAPP_CORPUS = ROOT / "simulator" / "data" / "raw_logs_newapp.txt"
ZENWALL_CORPUS = ROOT / "simulator" / "data" / "raw_logs_zenwall.txt"
ZENWALL_GOLDEN = ROOT / "libs" / "ulpf-core" / "tests" / "data" / "golden" / "raw_logs_zenwall.txt"

# Hand-authored rules (R-T12-pre-a: the newapp fallback is DISTINCT from G's
# generic pattern). Each targets the corpus's real shape; both pass the full
# validate_candidate gate against their corpus (checked host-side before the
# candidate is ever POSTed — same fast-fail discipline as the gateway).
# newapp: anchor the appliance envelope, map the KV extension keys per the
# §6.4 allow-list (ts/src/srcport/dst/dstport/action/msg).
NEWAPP_RULE = (
    r"^\S+ flowgate (?P<extension>.*)$",
    (("ts", "time"), ("src", "src_endpoint.ip"), ("srcport", "src_endpoint.port"),
     ("dst", "dst_endpoint.ip"), ("dstport", "dst_endpoint.port"),
     ("action", "action"), ("msg", "message")),
)
# zenwall: the generic extension-blob pattern (the AcmeGW story) — the whole
# line is one KV scan. The file's ONLY machine-readable KV key is `rule=`
# (src=/dst= sit behind `;` separators the KV grammar cannot split), so the
# only allow-listed mapping is rule -> message.
ZENWALL_RULE = (
    r"^.*?(?P<extension>.*)$",
    (("rule", "message"),),
)

# --- M3 (Task 12 asserts I-L): the firmware-drift demo on the seeded syslog rule --

SYSLOG_FP = "syslog"
QUARANTINE_FIELD = "src_endpoint.ip"  # the syslog rule's SRC mapping (seed 001)

# Demo drift knobs exported before compose up (Task 12 brief Step 1): windows
# close every 30 rows so the demo fits in minutes. The brief pinned
# WINDOW_TIME_S=15 as well, but on the ACCUMULATING DB that is unsound: the
# M1/M2-era rows are spread across days, and a 15 s time-close slices them
# into ~255 one-row windows at the very first scan — arming the syslog
# baseline from ten degenerate 1-row windows (null_rate 0.0), after which the
# tier-2 null ladder fires severe at ANY 5% null rate and deactivates the
# rule before the moderate quarantine (Assert J) can ever land (observed
# live). The smoke therefore pins a time horizon no demo gap can cross and
# lets windows close on COUNT only — deterministic 30-row boundaries the
# tuning math below models exactly.
DRIFT_WINDOW_COUNT = "30"
DRIFT_WINDOW_TIME_S = "1000000000"  # ~31.7 years: count-close only

# The drift-run tuning targets the FIRST FULLY-NEW 30-row window of the run
# (run rows offset+1 .. offset+30, where offset = current v1 view % 30) at a
# tier-1 violation_rate in [MIN, MAX] — comfortably moderate (> 0.20), safely
# below severe (0.50), with margin for +/-2 lines of send-time jitter.
J_WINDOW_MIN_VIOLATION = 0.27
J_WINDOW_MAX_VIOLATION = 0.43
J_WINDOW_TARGET_VIOLATION = 0.35
W_OLD_MAX_VIOLATION = 0.18  # the partial-completing window must stay minor

DRIFT_I_TIMEOUT_S = 120.0   # I: metrics row appears (tier-1 fires)
DRIFT_J_TIMEOUT_S = 120.0   # J: quarantine lands + a post-quarantine parsed event
DRIFT_K_TIMEOUT_S = 120.0   # K: deactivate + sample growth
DRIFT_L_TIMEOUT_S = 90.0    # L: un-quarantine + a clean mapped event
RULE_REFRESH_MARGIN_S = 6.0 # pipeline reloads active rules every batch (<= 2 s)

# K-maker: post-quarantine syslog parses are ALL null at src_endpoint.ip (the
# mapping is disabled), so any full 30-row window of them hits null_rate 1.0
# vs the ~0.017 baseline — ratio >= 40x, severe -> deactivate. Corruption
# content is irrelevant here (clean lines are nulls too once quarantined); the
# firmware-drift mode is used anyway to keep the demo narrative honest.
K_MAKER = {"eps": "25", "drift_after": "1", "duration": "15"}
# Probe/flush: brief steady runs (clean lines only). The probe supplies the
# post-quarantine parsed events J inspects; the flush proves L's mapping came
# back once clean lines flow after the human un-quarantine.
PROBE_RUN = {"eps": "4", "duration": "6"}
FLUSH_RUN = {"eps": "25", "duration": "8"}

# Restoration dance rule (NOT an assert input): the seed syslog pattern with
# every mapping EXCEPT SRC — sane on any corpus line (corruption only touches
# SRC), so the candidate gate passes even against corrupted onboarding
# samples, and the M2 backlog sweep re-parses the poisoned v1 rows under a
# version that does not even map src_endpoint.ip (no violations recorded).
SYSLOG_NO_SRC_RULE = (
    r"^.*?IPTABLES-\w+:\s*(?P<extension>.*)$",
    (("SPT", "src_endpoint.port"), ("DST", "dst_endpoint.ip"),
     ("DPT", "dst_endpoint.port")),
)
SYSLOG_CORPUS = ROOT / "simulator" / "data" / "raw_logs_syslog.txt"

# The simulator's deterministic corruption profile, replicated host-side for
# tuning (T11 constants; see simulator/simulate.py corrupt_syslog). The
# selector is a permutation of [0, 1) over any 1000 consecutive indices, so
# `selector < phase` corrupts exactly a `phase` fraction in expectation.
DRIFT_HASH_MULT = 2654435761
DRIFT_HASH_MOD = 1000

_SIM_LINE = re.compile(r"^(\w+) sent=(\d+)$", re.MULTILINE)
_LAG_LINE = re.compile(r"^TOTAL-LAG\s+(\S+)\s*$", re.MULTILINE)

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str) -> bool:
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")
    return ok


def compose(*args: str, timeout: float = 300) -> subprocess.CompletedProcess:
    # Explicit UTF-8 decoding: the default on Windows is the ANSI codepage
    # (cp1252 here), and docker output is UTF-8 — a stray byte crashed a
    # subprocess reader thread with UnicodeDecodeError.
    return subprocess.run(
        ["docker", "compose", *args], cwd=DEPLOY, capture_output=True,
        text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False,
    )


def http_get(url: str, timeout: float = 10) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, b""
    except (urllib.error.URLError, OSError, TimeoutError):
        # Transient stack stall (e.g. the SLM ladder saturating the box during
        # the candidate wait): poll loops must degrade to retry, not crash.
        # Status 0 = "no answer"; every caller treats it as keep-waiting/fail.
        return 0, b""


def http_json(url: str, timeout: float = 10) -> tuple[int, object]:
    status, raw = http_get(url, timeout=timeout)
    if not raw:
        return status, None
    try:
        return status, json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        return status, None


def q1(cur, sql: str, params=()):
    cur.execute(sql, params)
    return cur.fetchone()[0]


def db_count(sql: str) -> int:
    with psycopg.connect(DSN) as conn, conn.cursor() as cur:
        return q1(cur, sql)


def stats_by_fingerprint() -> dict[str, dict]:
    """{fingerprint_id: {total, parsed}} from GET /api/stats (delta base)."""
    status, body = http_json(f"{GATEWAY}/api/stats")
    if status != 200:
        raise RuntimeError(f"GET /api/stats -> {status}")
    return {row["fingerprint_id"]: {"total": row["total"], "parsed": row["parsed"]}
            for row in body["by_fingerprint"]}


def rpk(*args: str, timeout: float = 60) -> subprocess.CompletedProcess:
    return compose("exec", "-T", "redpanda", "rpk", *args, timeout=timeout)


def group_listed(listing: subprocess.CompletedProcess) -> bool:
    """True iff `rpk group list` output has a row whose GROUP column is exactly
    'pipeline' (a regex word-match would also hit e.g. 'pipeline-x')."""
    return listing.returncode == 0 and any(
        line.split()[-1:] == ["pipeline"] for line in listing.stdout.splitlines() if line.split()
    )


def wait_group_present(timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if group_listed(rpk("group", "list")):
            return True
        time.sleep(POLL_INTERVAL_S)
    return False


def wait_group_lag_zero(timeout_s: float) -> tuple[bool, str]:
    """Poll `rpk group describe pipeline` until TOTAL-LAG is 0."""
    deadline = time.monotonic() + timeout_s
    last = "no successful describe"
    while time.monotonic() < deadline:
        out = rpk("group", "describe", "pipeline")
        if out.returncode == 0:
            match = _LAG_LINE.search(out.stdout)
            if match:
                lag = match.group(1)
                last = f"TOTAL-LAG={lag}"
                if lag.isdigit() and int(lag) == 0:
                    return True, last
            else:
                last = f"no TOTAL-LAG line in describe output: {out.stdout[:200]!r}"
        else:
            last = f"describe rc={out.returncode}: {out.stderr.strip()[:120]}"
        time.sleep(POLL_INTERVAL_S)
    return False, last


def wait_drain(before_raw: int, before_norm: int, total_sent: int) -> tuple[bool, int, int]:
    """Poll until this run's raw and normalized deltas both equal total_sent."""
    deadline = time.monotonic() + DRAIN_TIMEOUT_S
    raw = norm = -1
    while time.monotonic() < deadline:
        raw = db_count("SELECT count(*) FROM raw_events") - before_raw
        norm = db_count("SELECT count(*) FROM normalized_events") - before_norm
        if raw == total_sent and norm == total_sent:
            return True, raw, norm
        time.sleep(POLL_INTERVAL_S)
    return False, raw, norm


def wait_http_ready(url: str, name: str, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status, _ = http_json(url, timeout=5)
            if status == 200:
                print(f"  {name} ready: {url} -> 200")
                return True
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            pass
        time.sleep(2.0)
    print(f"  {name} NOT ready within {timeout_s:.0f}s: {url}")
    return False


def fingerprint_split_table(before: dict, after: dict) -> str:
    lines = [f"    {'fingerprint':<20} {'delta':>6} {'total':>6} {'parsed':>7} {'unparsed':>9}"]
    for fp in sorted(set(before) | set(after)):
        total = after.get(fp, {}).get("total", 0)
        parsed = after.get(fp, {}).get("parsed", 0)
        delta = total - before.get(fp, {}).get("total", 0)
        lines.append(f"    {fp:<20} {delta:>6} {total:>6} {parsed:>7} {total - parsed:>9}")
    return "\n" + "\n".join(lines)


def step1_up() -> None:
    print("== Step 1: docker compose --profile slm-4b up -d --build + health wait ==")
    # --profile slm-4b: the onboarding service's SLM tier sidecar (R-T12-pre-b).
    out = compose("--profile", "slm-4b", "up", "-d", "--build", timeout=BUILD_TIMEOUT_S)
    if out.returncode != 0:
        print(out.stdout[-2000:])
        print(out.stderr[-2000:])
        sys.exit("FATAL: compose up failed; cannot run the smoke.")
    ok_gw = wait_http_ready(f"{GATEWAY}/api/stats", "gateway", READY_TIMEOUT_S)
    ok_web = wait_http_ready(f"{WEB}/", "web", READY_TIMEOUT_S)
    # onboarding readiness surface: /api/rules serves the M2 review API the
    # asserts poll (gateway up + migrations applied).
    ok_rules = wait_http_ready(f"{GATEWAY}/api/rules", "gateway M2 rules API", READY_TIMEOUT_S)
    ok_group = wait_group_present(READY_TIMEOUT_S)
    if not (ok_gw and ok_web and ok_rules and ok_group):
        sys.exit("FATAL: stack not ready (gateway/web/rules API/kafka group 'pipeline').")


def run_simulator(*, mode: str = "steady", eps: str | None = None,
                  duration: str | None = None, drift_after: str | None = None,
                  loop: bool = False, label: str = "Step 2") -> dict[str, int]:
    """`docker compose run` the simulator; defaults reproduce the M2 steady
    call byte-for-byte. M3 passes mode/eps/duration/drift_after/loop for the
    firmware-drift runs and the brief steady probes. Returns the parsed
    stdout contract dict ({corpus: sent, total: N})."""
    eps = SIM_EPS if eps is None else eps
    duration = SIM_DURATION if duration is None else duration
    args = ["--mode", mode, "--eps", eps, "--duration", duration]
    if drift_after is not None:
        args += ["--drift-after", drift_after]
    if loop:
        args.append("--loop")  # M3 only: repeat corpora so one run yields 30+ syslog rows
    print(f"== {label}: simulator --mode {mode} --eps {eps} --duration {duration}"
          + (f" --drift-after {drift_after}" if drift_after is not None else "")
          + (" --loop" if loop else "") + " ==")
    # --profile sim BEFORE run: the simulator service is profile-gated
    # (docker-compose.yml), and `docker compose run` refuses a gated service
    # whose profile is not active (R-T12-pre-b). --build: profile-gated
    # services are NOT built by `up --build` (their profile is inactive
    # there), so without this the run would use whatever image happened to
    # be built last — observed live in M3 Task 12 as an M2-era image without
    # firmware-drift mode. Cached layers make the rebuild cheap.
    out = compose("--profile", "sim", "run", "--rm", "-T", "--build", "simulator",
                  *args, timeout=SIM_TIMEOUT_S)
    sent = {name: int(n) for name, n in _SIM_LINE.findall(out.stdout)}
    if out.returncode != 0 or "total" not in sent:
        print("stdout:", out.stdout[-2000:])
        print("stderr:", out.stderr[-2000:])
        sys.exit("FATAL: simulator run failed or stdout contract broken.")
    corpora_total = sum(n for name, n in sent.items() if name != "total")
    missing = {"acmegw", "cef", "json", "syslog"} - set(sent)
    if missing or corpora_total != sent["total"]:
        sys.exit(f"FATAL: simulator stdout contract broken: {sent} (missing={missing})")
    # Deterministic delivery (live Task 12 finding): the collector's producer
    # rides librdkafka defaults, and under this box's load its queue delayed
    # messages by many minutes (and retry-duplicated corpora) — breaking K's
    # sample poll and G/H's deltas on otherwise-green runs. A graceful
    # collector restart runs the app's shutdown flush (uvicorn SIGTERM ->
    # lifespan -> producer.flush), draining the queue in seconds. The
    # collector is a stateless forwarder; the restart is benign.
    compose("restart", "collector", timeout=120)
    return sent


def assert_a(before_raw: int, total_sent: int) -> None:
    print("== Assert A: lossless (raw_events delta == sent) ==")
    raw_after = db_count("SELECT count(*) FROM raw_events")
    delta = raw_after - before_raw
    check("A lossless", delta == total_sent,
          f"sent={total_sent} raw_events delta={delta} (before={before_raw} after={raw_after})")


def active_rule_fingerprints() -> set[str]:
    """Fingerprints with an ACTIVE rule (GET /api/rules?status=active); empty
    set when the endpoint is down, so the unparsed check below stays strict.

    Assert B's 'auto_* must have parsed == 0' encodes M1's world where no auto
    fingerprint ever had a rule. M2's hero loop legitimately activates one —
    and the DB accumulates across runs, so from the first approved candidate
    onward that fingerprint parses BY DESIGN (the pipeline parses live traffic
    under active rules). The guarantee being regression-tested is conditional:
    an auto fingerprint with NO active rule must stay unparsed. Whenever no
    auto-fingerprint rule is active, this returns empty and assert_b behaves
    exactly as M1 wrote it."""
    status, body = http_json(f"{GATEWAY}/api/rules?status=active")
    if status != 200 or not body:
        return set()
    return {row["fingerprint_id"] for row in body.get("rules", [])}


def assert_b(before_fps: dict) -> None:
    print("== Assert B: parsed split via /api/stats by_fingerprint ==")
    after = stats_by_fingerprint()
    details = [fingerprint_split_table(before_fps, after)]
    ok = True
    problems = []
    seeded_delta = 0
    for fp in SEEDED_FPS:
        row = after.get(fp)
        if row is None or row["total"] == 0:
            ok = False
            problems.append(f"{fp}: absent/empty")
            continue
        seeded_delta += row["total"] - before_fps.get(fp, {}).get("total", 0)
        if row["parsed"] != row["total"]:
            ok = False
            problems.append(f"{fp}: parsed {row['parsed']}/{row['total']}")
    autos = {fp: row for fp, row in after.items() if fp.startswith("auto_")}
    auto_delta = sum(row["total"] - before_fps.get(fp, {}).get("total", 0)
                     for fp, row in autos.items())
    ruled_fps = active_rule_fingerprints() & set(autos)
    for fp, row in autos.items():
        if row["parsed"] != 0 and fp not in ruled_fps:
            ok = False
            problems.append(f"{fp}: parsed={row['parsed']} (must be 0)")
    if not autos or auto_delta == 0:
        ok = False
        problems.append("no auto_* fingerprint saw traffic (AcmeGW unparsed path unexercised)")
    total_sent_b = seeded_delta + auto_delta
    details.append(f"    seeded delta={seeded_delta}, auto delta={auto_delta}, sum={total_sent_b}")
    auto_note = "" if not ruled_fps else \
        f" (active-rule auto fps parsed by design: {', '.join(sorted(ruled_fps))})"
    check("B parsed split", ok, "; ".join(problems) if problems else
          f"5 seeded fingerprints fully parsed, rule-less auto_* fully unparsed{auto_note}"
          f"{details[0]}\n{details[1]}")


def assert_c() -> None:
    print(f"== Assert C: traceability ({TRACE_SAMPLE} random parsed events) ==")
    status, body = http_json(f"{GATEWAY}/api/events?status=parsed&limit=500")
    if status != 200 or not body or len(body.get("events", [])) < TRACE_SAMPLE:
        check("C traceability", False, f"GET /api/events -> {status}, "
              f"{0 if not body else len(body['events'])} parsed events available")
        return
    events = random.sample(body["events"], TRACE_SAMPLE)
    http_ok = sql_ok = 0
    problems = []
    with psycopg.connect(DSN) as conn, conn.cursor() as cur:
        for ev in events:
            event_id = ev["event_id"]
            rstatus, raw = http_json(f"{GATEWAY}/api/events/{event_id}/raw")
            if rstatus != 200:
                problems.append(f"{event_id}: /raw -> {rstatus}")
                continue
            digest = hashlib.sha256(raw["raw_text"].encode("utf-8")).hexdigest()
            if digest != raw["content_hash"]:
                problems.append(f"{event_id}: HTTP content_hash mismatch")
                continue
            http_ok += 1
            cur.execute(
                "SELECT r.content_hash, r.raw_text FROM normalized_events ne "
                "JOIN raw_events r ON r.raw_id = ne.raw_id "
                "AND r.received_at = ne.raw_received_at "
                "WHERE ne.event_id = %s::uuid AND ne.superseded_by_event_id IS NULL",
                (event_id,),
            )
            row = cur.fetchone()
            if row is None:
                problems.append(f"{event_id}: SQL join found no raw row")
                continue
            if hashlib.sha256(row[1].encode("utf-8")).hexdigest() != row[0]:
                problems.append(f"{event_id}: SQL content_hash mismatch")
                continue
            sql_ok += 1
    ok = http_ok == TRACE_SAMPLE and sql_ok == TRACE_SAMPLE
    check("C traceability", ok,
          f"HTTP /raw 200+hash {http_ok}/{TRACE_SAMPLE}, SQL join+hash {sql_ok}/{TRACE_SAMPLE}"
          + ("" if ok else "; problems: " + "; ".join(problems[:5])))


def replay_dance() -> tuple[bool, str]:
    """The M1 forced-replay dance: stop pipeline -> wait for the consumer to
    leave the group -> delete the consumer group -> start pipeline -> wait for
    lag 0. Extracted verbatim from assert_d_replay (Task 12) so Assert H can
    re-run the same dance after the M2 asserts; every branch here behaved
    identically inside assert_d_replay before the extraction."""
    # Order matters: the pipeline is stopped BEFORE the group delete. Deleted
    # while running, the live consumer's auto-rejoin recreates the group and
    # re-commits its offsets within seconds, so a restart afterwards would have
    # nothing to redeliver (vacuous replay, observed as raw_batches unchanged).
    stop = compose("stop", "pipeline", timeout=180)
    if stop.returncode != 0:
        return False, f"compose stop pipeline failed: {stop.stderr.strip()[:200]}"
    deadline = time.monotonic() + 60
    saw_members_zero = False
    last_detail = "group describe never succeeded"
    while time.monotonic() < deadline:  # consumer must be fully out of the group
        out = rpk("group", "describe", "pipeline")
        if out.returncode == 0 and re.search(r"^MEMBERS\s+0\s*$", out.stdout, re.MULTILINE):
            saw_members_zero = True
            break
        last_detail = (out.stderr.strip() or out.stdout.strip())[:120]
        time.sleep(POLL_INTERVAL_S)
    if saw_members_zero:
        print("  pipeline stopped; consumer has left the group")
    else:
        print(f"  timeout waiting for members=0, last={last_detail!r} (continuing)")

    listing = rpk("group", "list")
    if not group_listed(listing):
        return False, (f"kafka group 'pipeline' absent before delete (replay would be "
                       f"vacuous): {listing.stdout.strip()!r}")
    delete = rpk("group", "delete", "pipeline")
    if delete.returncode != 0:
        return False, (f"rpk group delete failed rc={delete.returncode}: "
                       f"{delete.stderr.strip()[:200]}")
    print("  group 'pipeline' deleted (committed offsets dropped); starting pipeline")
    start = compose("start", "pipeline", timeout=180)
    if start.returncode != 0:
        return False, f"compose start pipeline failed: {start.stderr.strip()[:200]}"
    lag_ok, lag_detail = wait_group_lag_zero(LAG_TIMEOUT_S)
    if not lag_ok:
        return False, f"group lag never reached 0: {lag_detail}"
    print(f"  replay drained ({lag_detail})")
    return True, lag_detail


def wait_batches_stable(window_s: float = 3.0, timeout_s: float = 90.0) -> int:
    """After the replay dance reports lag 0, wait until raw_batches stops
    moving and return its count.

    The worker commits offsets only AFTER its persist transactions, so lag 0
    should imply the replay's batches are durable — but a lag poll can hit
    the window where the recreated group exists WITHOUT committed offsets
    (observed live: rpk reported 0 before the redelivered batches landed),
    which would make the post-replay snapshots early. Gating on the batch
    count being quiet across a full poll window removes that race.
    """
    deadline = time.monotonic() + timeout_s
    last = db_count("SELECT count(*) FROM raw_batches")
    last_change = time.monotonic()
    while time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL_S)
        current = db_count("SELECT count(*) FROM raw_batches")
        if current != last:
            last, last_change = current, time.monotonic()
        elif time.monotonic() - last_change >= window_s:
            return current
    return last


def assert_d_replay() -> None:
    print("== Assert D: forced replay (group delete + pipeline restart) ==")
    pre_raw = db_count("SELECT count(*) FROM raw_events")
    pre_batches = db_count("SELECT count(*) FROM raw_batches")
    pre_fps = stats_by_fingerprint()

    danced, dance_detail = replay_dance()
    if not danced:
        check("D replay idempotency", False, dance_detail)
        return
    post_batches = wait_batches_stable()

    post_raw = db_count("SELECT count(*) FROM raw_events")
    post_fps = stats_by_fingerprint()
    summary = (
        f"raw_events {pre_raw}->{post_raw}, raw_batches {pre_batches}->{post_batches}, "
        f"split unchanged={pre_fps == post_fps}"
    )
    details = [summary]
    ok = (post_raw == pre_raw and post_batches > pre_batches and pre_fps == post_fps)
    if pre_fps != post_fps:
        details.append(fingerprint_split_table(pre_fps, post_fps))
    check("D replay idempotency", ok,
          f"raw_events unchanged={post_raw == pre_raw}, raw_batches grew "
          f"{pre_batches}->{post_batches}, by_fingerprint unchanged={pre_fps == post_fps}; "
          + "; ".join(details))


def assert_e_chain() -> None:
    print("== Assert E: full per-partition chain walk + independent root recompute ==")
    with psycopg.connect(DSN) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT partition_id, batch_seq, prev_hash, merkle_root, row_hashes, count "
            "FROM raw_batches ORDER BY partition_id, batch_seq"
        )
        rows = cur.fetchall()
    if not rows:
        check("E chain continuity", False, "raw_batches is empty")
        return
    chains: dict[int, list] = {}
    for partition_id, batch_seq, prev_hash, root, row_hashes, count in rows:
        chains.setdefault(partition_id, []).append(
            (batch_seq, prev_hash, root, row_hashes, count))
    problems = []
    n_verified = 0
    for partition_id in sorted(chains):
        chain = sorted(chains[partition_id])
        for position, (batch_seq, prev_hash, root, row_hashes, count) in enumerate(chain):
            if position == 0:
                if batch_seq != 1 or prev_hash != GENESIS_PREV_HASH:
                    problems.append(f"p{partition_id}: bad genesis "
                                    f"(seq={batch_seq}, prev_hash={prev_hash[:12]}...)")
            else:
                if batch_seq != chain[position - 1][0] + 1:
                    problems.append(f"p{partition_id}: batch_seq gap at {batch_seq}")
                if prev_hash != chain[position - 1][2]:
                    problems.append(f"p{partition_id}: prev_hash link broken at seq {batch_seq}")
            if count != len(row_hashes):
                problems.append(f"p{partition_id} seq {batch_seq}: count {count} != "
                                f"len(row_hashes) {len(row_hashes)}")
            recomputed = merkle_root(list(row_hashes))
            if recomputed != root:
                problems.append(f"p{partition_id} seq {batch_seq}: stored root != "
                                f"merkle_root(row_hashes)")
            n_verified += 1
    ok = not problems
    parts = ", ".join(f"p{p}={len(chains[p])} batches" for p in sorted(chains))
    check("E chain continuity", ok,
          f"{n_verified} batches across {len(chains)} partition(s) "
          f"({parts}); every prev_hash link + every merkle root recomputed & matched"
          + ("" if ok else "; problems: " + "; ".join(problems[:5])))


# --- M2: onboarding hero loop (Task 12 asserts F/G/H) ---------------------------

def http_post_json(url: str, payload: dict, timeout: float = 30) -> tuple[int, object]:
    """POST JSON, return (status, decoded body). 4xx/5xx bodies are decoded
    too (the gateway's 422 carries {checks, notes} the assert should quote)."""
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    except (urllib.error.URLError, OSError, TimeoutError):
        return 0, None  # network-level failure; no auto-retry (see below)
    try:
        return status, json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return status, None


def read_corpus_lines(path: Path) -> list[str]:
    lines = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not lines:
        sys.exit(f"FATAL: corpus {path} is empty.")
    return lines


def corpus_fingerprint(lines: list[str], name: str) -> str:
    """The corpus's single fingerprint_id, computed host-side exactly as the
    pipeline mints it (same ulpf_core.fingerprint function)."""
    fps = {fingerprint_id(ln) for ln in lines}
    if len(fps) != 1:
        sys.exit(f"FATAL: {name} corpus spans {len(fps)} fingerprints: {sorted(fps)}")
    return fps.pop()


def ensure_zenwall_corpus() -> list[str]:
    """G's corpus: simulator/data/raw_logs_zenwall.txt; copied from the golden
    original when absent (the copy is inert to the simulator — load_corpora
    iterates the fixed CORPUS_KEYS, not the directory)."""
    if not ZENWALL_CORPUS.exists():
        ZENWALL_CORPUS.write_text(ZENWALL_GOLDEN.read_text(encoding="utf-8"),
                                  encoding="utf-8", newline="\n")
        print(f"  copied golden zenwall corpus -> {ZENWALL_CORPUS.relative_to(ROOT)}")
    return read_corpus_lines(ZENWALL_CORPUS)


def post_corpus(lines: list[str], source_id: str) -> int:
    """POST the whole corpus x5 to the collector (new HTTP raw events each
    time: raw_id is topic/partition/offset-derived, so repeats accumulate)."""
    accepted = 0
    for _ in range(5):
        status, body = http_post_json(
            f"{COLLECTOR}/v1/ingest", {"source_id": source_id, "lines": lines})
        if status != 202 or not isinstance(body, dict):
            sys.exit(f"FATAL: POST {source_id} corpus -> {status}: {body!r}")
        accepted += int(body.get("accepted", 0))
    return accepted


def wait_samples_total(fp: str, minimum: int, timeout_s: float) -> int:
    """Poll /api/onboarding/samples?fingerprint= until total >= minimum."""
    deadline = time.monotonic() + timeout_s
    total = -1
    while time.monotonic() < deadline:
        status, body = http_json(f"{GATEWAY}/api/onboarding/samples?fingerprint={fp}")
        if status == 200 and isinstance(body, dict):
            total = int(body.get("total", 0))
            if total >= minimum:
                return total
        time.sleep(POLL_INTERVAL_S)
    return total


def pending_candidate_for(fp: str) -> dict | None:
    status, body = http_json(f"{GATEWAY}/api/rules?status=pending_review")
    if status == 200 and isinstance(body, dict):
        for rule in body.get("rules", []):
            if rule.get("fingerprint_id") == fp:
                return rule
    return None


def wait_pending_candidate(fp: str, timeout_s: float) -> dict | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        candidate = pending_candidate_for(fp)
        if candidate is not None:
            return candidate
        time.sleep(POLL_INTERVAL_S)
    return None


def supersede_counts(fp: str) -> tuple[int, int]:
    """(unsuperseded, superseded) normalized_events rows for the fingerprint —
    the pre-approve snapshot pair R-T12-pre-d's delta assert needs."""
    with psycopg.connect(DSN) as conn, conn.cursor() as cur:
        unsup = q1(cur, "SELECT count(*) FROM normalized_events "
                        "WHERE fingerprint_id=%s AND superseded_by_event_id IS NULL", (fp,))
        sup = q1(cur, "SELECT count(*) FROM normalized_events "
                      "WHERE fingerprint_id=%s AND superseded_by_event_id IS NOT NULL", (fp,))
    return unsup, sup


def wait_fingerprint_quiet(fp: str, window_s: float = 3.0, timeout_s: float = 90.0) -> int:
    """Wait until the fingerprint's normalized_events row count stops moving
    and return the quiet total (unsuperseded + superseded).

    The manual path (G) creates its candidate within seconds of posting the
    corpus, so the pre-approve snapshots can fire while posted events are
    still in flight (collector -> kafka -> pipeline). Without this gate the
    late rows land AFTER the approve-time sweep and parse in-flight under the
    now-active rule, making the current view grow past the pre-approve
    unsuperseded count (observed live in run B: total 50 -> 100). Gating the
    snapshots on a quiet count makes the per-run deltas deterministic; assert
    semantics are unchanged."""
    deadline = time.monotonic() + timeout_s
    last = sum(supersede_counts(fp))
    last_change = time.monotonic()
    while time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL_S)
        current = sum(supersede_counts(fp))
        if current != last:
            last, last_change = current, time.monotonic()
        elif time.monotonic() - last_change >= window_s:
            return last
    return last


def sample_count(fp: str) -> int:
    with psycopg.connect(DSN) as conn, conn.cursor() as cur:
        return q1(cur, "SELECT count(*) FROM onboarding_samples WHERE fingerprint_id=%s", (fp,))


def validate_local_rule(fp: str, rule_spec, lines: list[str]) -> object:
    """Fast-fail discipline (as G): run the hand-authored rule through the SAME
    deterministic gate the gateway enforces server-side, against the corpus
    lines in the onboarding split shape (5 prompt / rest held-out)."""
    pattern, mappings = rule_spec
    rule = Rule(fingerprint_id=fp, version=1, pattern=pattern, provenance="human",
                mappings=[Mapping(source_field=s, ocsf_path=o) for s, o in mappings])
    return validate_candidate(rule, lines[:5], lines[5:20])


def post_manual_candidate(fp: str, rule_spec) -> tuple[int, dict | None]:
    pattern, mappings = rule_spec
    return http_post_json(f"{GATEWAY}/api/rules/manual", {
        "fingerprint_id": fp,
        "pattern": pattern,
        "mappings": [{"source_field": s, "ocsf_path": o} for s, o in mappings],
        "actor": "smoke",
    })


def acquire_candidate(fp: str, lines: list[str], rule_spec) -> tuple[dict | None, bool, str]:
    """R-T12-pre-a candidate acquisition for F: poll pending_review for an SLM
    candidate (ULPF_SMOKE_SLM_WAIT_S, default 300s); on timeout author one
    deterministically — local validate_candidate fast-fail, then POST
    /api/rules/manual -> 201 (manual creation is gate-passed by construction).
    Returns (candidate, ok, acquisition_detail); candidate None on failure with
    the reason in detail."""
    print(f"  polling pending_review for an SLM candidate "
          f"(timeout {SLM_WAIT_TIMEOUT_S}s; qwen3:4b on an 8GB host is expected "
          f"to store 0 rules — the manual fallback is the ruled outcome)")
    candidate = wait_pending_candidate(fp, SLM_WAIT_TIMEOUT_S)
    if candidate is not None:
        validation = candidate.get("validation") or {}
        checks = validation.get("checks") or {}
        ok = validation.get("passed") is True and bool(checks) and all(checks.values())
        detail = (f"SLM candidate id={candidate.get('id')} v{candidate.get('version')} "
                  f"validation.passed={validation.get('passed')} checks={checks}")
        return candidate, ok, detail

    report = validate_local_rule(fp, rule_spec, lines)
    if not report.passed:
        return None, False, (f"SLM wait expired AND hand-authored rule failed the local "
                             f"gate: checks={report.checks} notes={report.notes[:3]}")
    status, body = post_manual_candidate(fp, rule_spec)
    print(f"  SLM wait expired after {SLM_WAIT_TIMEOUT_S}s — recorded limitation of the "
          f"default qwen3:4b tier (0 rules stored, 0.0 held-out confidence; see "
          f"docs/m2-slm-sanity.md). Falling back to the hand-authored manual candidate.")
    if status != 201 or not isinstance(body, dict) or "rule_id" not in body:
        return None, False, (f"SLM wait expired AND POST /api/rules/manual -> {status}: "
                             f"{body!r}")
    detail = (f"SLM wait expired after {SLM_WAIT_TIMEOUT_S}s (qwen3:4b stores 0 rules on "
              f"this host — recorded limitation, docs/m2-slm-sanity.md): manual candidate "
              f"id={body['rule_id']} v{body.get('version')} POST -> 201")
    return {"id": body["rule_id"], "version": body.get("version")}, True, detail

def wait_reparse_complete(fp: str, version: int, timeout_s: float) -> dict | None:
    """Poll /api/audit until a reparse_complete row exists with
    detail.version == the approved rule's version (R-T12-pre-d: the audit row
    is the deterministic completion signal — a parsed==total poll cannot
    signal completion on a re-run, because with a v1 rule active new lines
    parse in-flight before the approval)."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status, body = http_json(f"{GATEWAY}/api/audit?fingerprint={fp}&limit={AUDIT_PAGE}")
        if status == 200 and isinstance(body, dict):
            for row in body.get("audit", []):
                detail = row.get("detail") or {}
                if row.get("action") == "reparse_complete" and detail.get("version") == version:
                    return detail
        time.sleep(POLL_INTERVAL_S)
    return None


def audit_has(fp: str, action: str, want: dict) -> bool:
    """True iff the fingerprint's audit trail has an `action` row whose detail
    contains every key=value in want."""
    status, body = http_json(f"{GATEWAY}/api/audit?fingerprint={fp}&limit={AUDIT_PAGE}")
    if status != 200 or not isinstance(body, dict):
        return False
    for row in body.get("audit", []):
        detail = row.get("detail") or {}
        if row.get("action") == action and all(detail.get(k) == v for k, v in want.items()):
            return True
    return False


def approve_and_reparse(fp: str, candidate: dict) -> tuple[bool, list[str], list[str]]:
    """Approve the candidate and verify the R11 backlog sweep by per-run
    deltas (R-T12-pre-d): superseded-count DELTA == the pre-approve
    unsuperseded count, completion via the reparse_complete audit row for the
    approved version, and the current view fully parsed at an unchanged total.
    Returns (ok, detail_parts, problems)."""
    problems: list[str] = []
    candidate_id = candidate.get("id")

    # Per-run deltas (R-T12-pre-d). The quiet gate first: posted backlog must
    # have fully landed before the pre-approve snapshots (see the helper).
    quiet_total = wait_fingerprint_quiet(fp)

    # Pre-approve snapshots (per-run deltas — the DB accumulates prior runs).
    pre_fps = stats_by_fingerprint().get(fp, {})
    unsup_pre, sup_pre = supersede_counts(fp)
    if unsup_pre + sup_pre != quiet_total:
        problems.append(f"fingerprint row count moved during snapshot "
                        f"(quiet={quiet_total}, snapshot={unsup_pre + sup_pre})")

    status, body = http_post_json(
        f"{GATEWAY}/api/rules/{fp}/candidates/{candidate_id}/approve", {"actor": "smoke"})
    if status != 200 or not isinstance(body, dict):
        msg = f"approve POST -> {status}: {body!r}"
        return False, [msg], [msg]
    version = body.get("version")
    parts = [f"approve -> 200 v{version}"]

    reparse = wait_reparse_complete(fp, version, REPARSE_TIMEOUT_S)
    if reparse is None:
        problems.append(f"no reparse_complete v{version} audit row within "
                        f"{REPARSE_TIMEOUT_S:.0f}s")
    else:
        parts.append(f"reparse_complete v{version} inserted={reparse.get('inserted')} "
                     f"superseded={reparse.get('superseded')}")

    sup_post = supersede_counts(fp)[1]
    sup_delta = sup_post - sup_pre
    parts.append(f"superseded delta {sup_pre}->{sup_post} (delta {sup_delta})")
    if sup_delta != unsup_pre:
        problems.append(f"superseded delta {sup_delta} != pre-approve unsuperseded "
                        f"{unsup_pre}")
    if reparse is not None and (reparse.get("inserted") != unsup_pre
                                or reparse.get("superseded") != unsup_pre):
        problems.append(f"reparse_complete counts {reparse.get('inserted')}/"
                        f"{reparse.get('superseded')} != {unsup_pre}")

    post_fp = stats_by_fingerprint().get(fp, {})
    parts.append(f"stats total {pre_fps.get('total')}->{post_fp.get('total')}, "
                 f"parsed -> {post_fp.get('parsed')}")
    if post_fp.get("parsed") != post_fp.get("total"):
        problems.append(f"current view not fully parsed: {post_fp}")
    elif post_fp.get("total") != unsup_pre:
        problems.append(f"current-view total {post_fp.get('total')} changed from the "
                        f"pre-approve unsuperseded count {unsup_pre}")
    if not audit_has(fp, "rule_approved", {"rule_id": candidate_id, "version": version}):
        problems.append(f"no rule_approved audit row for candidate {candidate_id} v{version}")
    else:
        parts.append("audit rule_approved present")
    return not problems, parts, problems


def assert_hero_loop(check_name: str, label: str, fp: str, lines: list[str],
                     source_id: str, rule_spec, slm_poll: bool) -> None:
    """F/G shared body: post the corpus x5, wait for onboarding samples, take a
    pending_review candidate through approve -> backlog re-parse (F polls for
    an SLM candidate first per R-T12-pre-a; G posts the hand-authored rule
    directly — deterministic, no SLM)."""
    print(f"== Assert {check_name}: {label} (fingerprint {fp}) ==")
    accepted = post_corpus(lines, source_id)
    total = wait_samples_total(fp, 20, SAMPLES_WAIT_TIMEOUT_S)
    if total < 20:
        check(check_name, False, f"onboarding samples for {fp} never reached 20 "
              f"(posted={accepted}, last total={total})")
        return

    if slm_poll:
        candidate, ok, detail = acquire_candidate(fp, lines, rule_spec)
    else:
        report = validate_local_rule(fp, rule_spec, lines)
        if not report.passed:
            check(check_name, False, f"hand-authored rule failed the local gate: "
                  f"checks={report.checks} notes={report.notes[:3]}")
            return
        status, body = post_manual_candidate(fp, rule_spec)
        ok = status == 201 and isinstance(body, dict) and "rule_id" in body
        detail = (f"manual candidate id={body.get('rule_id')} v{body.get('version')} "
                  f"POST -> {status}" if ok else
                  f"POST /api/rules/manual -> {status}: {body!r}")
        candidate = ({"id": body["rule_id"], "version": body.get("version")}
                     if ok else None)
    if not ok:
        check(check_name, False, detail)
        return

    reparse_ok, parts, problems = approve_and_reparse(fp, candidate)
    detail_line = f"{detail}; " + "; ".join(parts)
    if not reparse_ok:
        detail_line += "; PROBLEMS: " + "; ".join(problems)
    check(check_name, reparse_ok, detail_line)


def assert_f_hero(lines: list[str], fp: str) -> None:
    assert_hero_loop("F hero loop (newapp)", "SLM candidate -> approve -> backlog re-parse",
                     fp, lines, NEWAPP_SOURCE, NEWAPP_RULE, slm_poll=True)


def assert_g_manual(lines: list[str], zfp: str) -> None:
    assert_hero_loop("G manual rule (zenwall)",
                     "hand-authored rule -> manual create -> approve -> re-parse",
                     zfp, lines, ZENWALL_SOURCE, ZENWALL_RULE, slm_poll=False)


def assert_h(fp: str, zfp: str) -> None:
    print("== Assert H: replay stability with active rules (samples included) ==")
    pre_raw = db_count("SELECT count(*) FROM raw_events")
    pre_norm = db_count("SELECT count(*) FROM normalized_events")
    pre_batches = db_count("SELECT count(*) FROM raw_batches")
    pre_fps = stats_by_fingerprint()
    pre_fp_samples = sample_count(fp)
    pre_zfp_samples = sample_count(zfp)

    danced, dance_detail = replay_dance()
    if not danced:
        check("H replay stability", False, dance_detail)
        return
    post_batches = wait_batches_stable()

    post_raw = db_count("SELECT count(*) FROM raw_events")
    post_norm = db_count("SELECT count(*) FROM normalized_events")
    post_fps = stats_by_fingerprint()
    post_fp_samples = sample_count(fp)
    post_zfp_samples = sample_count(zfp)

    problems = []
    if post_raw != pre_raw:
        problems.append(f"raw_events {pre_raw}->{post_raw}")
    if post_norm != pre_norm:
        problems.append(f"normalized_events {pre_norm}->{post_norm}")
    if post_batches <= pre_batches:
        problems.append(f"raw_batches did not grow: {pre_batches}->{post_batches} "
                        "(replay was vacuous)")
    if post_fps != pre_fps:
        problems.append("by_fingerprint changed:\n" + fingerprint_split_table(pre_fps, post_fps))
    if post_fp_samples != pre_fp_samples:
        problems.append(f"samples[{fp}] {pre_fp_samples}->{post_fp_samples}")
    if post_zfp_samples != pre_zfp_samples:
        problems.append(f"samples[{zfp}] {pre_zfp_samples}->{post_zfp_samples}")
    check("H replay stability", not problems,
          f"raw {pre_raw} unchanged, normalized {pre_norm} unchanged, raw_batches "
          f"{pre_batches}->{post_batches}, by_fingerprint unchanged, samples[{fp}]="
          f"{post_fp_samples} unchanged, samples[{zfp}]={post_zfp_samples} unchanged "
          "(unique raw_id dedup live with active rules)"
          + ("" if not problems else "; PROBLEMS: " + "; ".join(problems)))


# --- M3: drift demo asserts I-L (Task 12 Steps 2-5) -------------------------------

_SEVERITY_RANK = {name: rank for rank, name in
                  enumerate(("none", "minor", "moderate", "severe"))}


def _parse_ts(value) -> datetime:
    """API timestamp (ISO-8601 string or datetime) -> aware UTC datetime."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not value:
        return datetime.min.replace(tzinfo=UTC)
    parsed = datetime.fromisoformat(str(value))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _selector(index: int) -> float:
    """simulator.corrupt_syslog's deterministic per-line corruption selector
    (host-side replica for run tuning — the seed IS the corpus line index)."""
    return (index * DRIFT_HASH_MULT % DRIFT_HASH_MOD) / DRIFT_HASH_MOD


def _row_outcome(k: int, rate: float, drift_after: str, duration: str,
                 corpus_lines: int) -> tuple[bool, bool]:
    """(violates, nulls) for the k-th syslog send (1-based) of ONE simulator
    run at `rate` syslog lines/s — replica of simulator.corrupt_syslog: send
    time t = k/rate (one syslog line per round-robin pass), phase ramping
    from drift_after over the escalation span, corrupted iff
    selector((k-1) % corpus_lines) < phase, and among the corrupted 1 in 3
    (by corpus index) renames SRC->SRCADDR (a null) while the rest write the
    invalid SRC value (a tier-1 violation)."""
    t = k / rate
    a = float(drift_after)
    if t <= a:
        return False, False
    span = max(float(duration) - a, 1.0)
    phase = min(max((t - a) / span, 0.0), 1.0)
    index = (k - 1) % corpus_lines
    if _selector(index) < phase:
        return index % 3 != 0, index % 3 == 0
    return False, False


def _window_counts(segments, corpus_lines: int) -> tuple[int, int]:
    """(violations, nulls) over one 30-row window assembled from consecutive
    pieces of one or two simulator runs. Each segment is (first_k, n_rows,
    eps, drift_after, duration): sends first_k..first_k+n_rows-1 of a run
    with those parameters (send numbering restarts per run — each
    `compose run` is a fresh process with fresh cursors)."""
    viol = nulls = 0
    for first_k, n, eps, drift_after, duration in segments:
        rate = float(eps) / 4.0
        for k in range(first_k, first_k + n):
            v, nu = _row_outcome(k, rate, drift_after, duration, corpus_lines)
            viol += int(v)
            nulls += int(nu)
    return viol, nulls


def tune_drift_run(offset: int, corpus_lines: int) -> dict:
    """Plan the firmware-drift simulator run(s) for THIS run's view offset.

    The drift service closes a window every 30 current-view rows of the
    ACTIVE version. offset = view%30 decides the shape: with offset == 0 the
    run's first 30 rows are themselves the next closed window — which is also
    the ESTABLISHING 10th window (the DB history has exactly 9 windows, a
    verified M3 starting condition; once a baseline exists this window is
    simply the next one and the same math holds, see below). With offset > 0
    the run's first E = 30-offset rows complete the older partial (the
    establishing window), and the J-window is the NEXT one.

    The quarantine (J) must land on a window whose window_start is INSIDE
    this run (I's delta filter and J's poll both key off fresh rows): with
    offset == 0 the run's first 30 rows are that window. With offset > 0 the
    run's first E = 30-offset rows complete the OLDER partial — that window
    STARTS on a prior-run row, so it must stay MINOR (the quarantine must not
    land there: its metrics row is invisible to I's window_start filter and
    its scan races the null-severe deactivate) — and the NEXT window, built
    from the main run's fresh rows, is the J-window. The plan guarantees:

    - the J-window's deterministic violation_rate lands in
      [J_WINDOW_MIN, J_WINDOW_MAX] — moderate with margin on both sides,
      robust to +/-2 lines of send-time jitter;
    - the establishing window (offset > 0) stays minor (< W_OLD_MAX
      violations), so the moderate decision — and I's fresh metrics row —
      both arrive at the J-window's scan, before any severe window.

    Returns {"runs": [params...] to execute in order, "j_violation": float,
    "j_nulls": int, "establishing_violation": float}; params dicts are
    run_simulator kwargs (mode/loop added by the caller).
    """
    def rate_of(eps):
        return float(eps) / 4.0

    space = []
    if offset == 0:
        # One run: its rows 1..30 are the J-window (and the establishing one).
        for eps in ("6", "8", "10"):
            rate = rate_of(eps)
            for drift_after in ("0", "1", "2"):
                duration = 30 / rate + 1.0
                while duration <= 30 / rate + 10.0:
                    d = f"{duration:.1f}"
                    viol, nulls = _window_counts(
                        [(1, 30, eps, drift_after, d)], corpus_lines)
                    space.append({"runs": [{"eps": eps, "drift_after": drift_after,
                                            "duration": d}],
                                  "j_violation": viol / 30, "j_nulls": nulls,
                                  "est_violation": viol / 30, "est_nulls": nulls,
                                  "segments": [(1, 30, eps, drift_after, d)]})
                    duration += 0.5
    else:
        est_rows = 30 - offset
        # Two runs: a short PRE-RUN completes the establishing window (kept
        # minor); the MAIN run (fresh cursors) supplies the J-window's bulk.
        # The pre-run may overflow by 0-2 rows into the J-window's head.
        for pre_eps in ("4", "6", "8", "10"):
            pre_rate = rate_of(pre_eps)
            for pre_a in ("0", "1", "2", "3"):
                pre_d = est_rows / pre_rate + 0.1
                while pre_d <= est_rows / pre_rate + 0.9:
                    pd = f"{pre_d:.1f}"
                    pre_rows = min(max(math.ceil(pre_rate * float(pd)), est_rows),
                                   est_rows + 2)
                    est_viol, est_nulls = _window_counts(
                        [(1, est_rows, pre_eps, pre_a, pd)], corpus_lines)
                    overflow = pre_rows - est_rows
                    if est_viol >= W_OLD_MAX_VIOLATION * 30:
                        pre_d += 0.2
                        continue
                    for eps in ("6", "8", "10"):
                        rate = rate_of(eps)
                        for drift_after in ("0", "1", "2"):
                            main_rows = 30 - overflow
                            duration = main_rows / rate + 1.0
                            while duration <= main_rows / rate + 8.0:
                                d = f"{duration:.1f}"
                                segments = []
                                if overflow:
                                    segments.append((est_rows + 1, overflow,
                                                     pre_eps, pre_a, pd))
                                segments.append((1, main_rows, eps, drift_after, d))
                                viol, nulls = _window_counts(segments, corpus_lines)
                                space.append({
                                    "runs": [{"eps": pre_eps, "drift_after": pre_a,
                                              "duration": pd},
                                             {"eps": eps, "drift_after": drift_after,
                                              "duration": d}],
                                    "j_violation": viol / 30, "j_nulls": nulls,
                                    "est_violation": est_viol / 30,
                                    "est_nulls": est_nulls, "segments": segments})
                                duration += 0.5
                    pre_d += 0.2
    tiers = [
        lambda c: J_WINDOW_MIN_VIOLATION <= c["j_violation"] <= J_WINDOW_MAX_VIOLATION,
        lambda c: 0.22 <= c["j_violation"] <= 0.48,
        lambda c: 0.20 <= c["j_violation"] < 0.50,
    ]
    if not space:
        # No pre-run kept the establishing window minor — fall back to any
        # pre-run params (the quarantine may land on the old-started window;
        # I/J then depend on the main run's own windows). Loud, never silent.
        print("  WARNING: no pre-run kept the establishing window minor; "
              "falling back to untuned pre-run")
        pre_eps, pre_a = "6", "2"
        pd = f"{est_rows / rate_of(pre_eps) + 0.5:.1f}"
        for eps in ("6", "8", "10"):
            rate = rate_of(eps)
            for drift_after in ("0", "1", "2"):
                d = f"{30 / rate + 5.0:.1f}"
                viol, nulls = _window_counts(
                    [(1, 30, eps, drift_after, d)], corpus_lines)
                space.append({"runs": [{"eps": pre_eps, "drift_after": pre_a,
                                        "duration": pd},
                                       {"eps": eps, "drift_after": drift_after,
                                        "duration": d}],
                              "j_violation": viol / 30, "j_nulls": nulls,
                              "est_violation": 1.0, "est_nulls": 0,
                              "segments": [(1, 30, eps, drift_after, d)]})
    chosen = None
    for tier_no, tier in enumerate(tiers):
        pool = [c for c in space if tier(c)]
        if pool:
            chosen = min(pool, key=lambda c: abs(c["j_violation"] - J_WINDOW_TARGET_VIOLATION))
            if tier_no > 0:
                print(f"  WARNING: drift-run tuning relaxed to tier {tier_no + 1} "
                      f"(J-window violation={chosen['j_violation']:.3f})")
            break
    if chosen is None:
        chosen = min(space, key=lambda c: abs(c["j_violation"] - J_WINDOW_TARGET_VIOLATION))
        print(f"  WARNING: drift-run tuning fell back to closest "
              f"violation_rate={chosen['j_violation']:.3f} (no candidate met the bands)")
    return chosen


def active_rule(fp: str) -> dict | None:
    status, body = http_json(f"{GATEWAY}/api/rules?status=active")
    if status != 200 or not isinstance(body, dict):
        return None
    for rule in body.get("rules", []):
        if rule.get("fingerprint_id") == fp:
            return rule
    return None


def syslog_view_count(version) -> int:
    """Rows of the ACTIVE version's current view — the drift service's window
    input; offset = count % 30 decides where this run's rows slice."""
    with psycopg.connect(DSN) as conn, conn.cursor() as cur:
        return q1(cur, "SELECT count(*) FROM normalized_events "
                       "WHERE fingerprint_id=%s AND rule_version=%s "
                       "AND superseded_by_event_id IS NULL", (SYSLOG_FP, version))


def audit_after(fp: str, action: str, *, actor: str | None = None,
                after: datetime | None = None, want: dict | None = None) -> dict | None:
    """Newest matching audit row, or None. `after` bounds ts strictly (delta
    base: prior-run rows excluded); `want` matches detail key-values."""
    status, body = http_json(f"{GATEWAY}/api/audit?fingerprint={fp}&limit={AUDIT_PAGE}")
    if status != 200 or not isinstance(body, dict):
        return None
    for row in body.get("audit", []):
        detail = row.get("detail") or {}
        if row.get("action") != action:
            continue
        if actor is not None and row.get("actor") != actor:
            continue
        if want and not all(detail.get(k) == v for k, v in want.items()):
            continue
        if after is not None and _parse_ts(row.get("ts")) <= after:
            continue
        return row
    return None


def wait_parsed_event(after_ts: datetime, predicate, timeout_s: float) -> dict | None:
    """Poll the newest 50 parsed syslog events until one satisfies
    predicate(event, after_ts); None on timeout."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status, body = http_json(
            f"{GATEWAY}/api/events?fingerprint={SYSLOG_FP}&status=parsed&limit=50")
        if status == 200 and isinstance(body, dict):
            for ev in body.get("events") or []:
                try:
                    if predicate(ev, after_ts):
                        return ev
                except (KeyError, TypeError, ValueError):
                    continue
        time.sleep(POLL_INTERVAL_S)
    return None


def _j_event_ok(ev: dict, after_ts: datetime) -> bool:
    """J's post-quarantine parse: the SRC value preserved under
    ocsf.unmapped.SRC, src_endpoint.ip absent (mapping disabled)."""
    ocsf = ev.get("ocsf") or {}
    unmapped = ocsf.get("unmapped") or {}
    src = ocsf.get("src_endpoint") or {}
    return (_parse_ts(ev.get("parsed_at")) > after_ts
            and unmapped.get("SRC") is not None
            and "ip" not in src)


def _l_event_ok(ev: dict, after_ts: datetime) -> bool:
    """L's post-un-quarantine parse: src_endpoint.ip mapped again, SRC no
    longer dangling in unmapped."""
    ocsf = ev.get("ocsf") or {}
    unmapped = ocsf.get("unmapped") or {}
    src = ocsf.get("src_endpoint") or {}
    return (_parse_ts(ev.get("parsed_at")) > after_ts
            and isinstance(src.get("ip"), str) and src["ip"] != ""
            and "SRC" not in unmapped)


def assert_i_tier1(run_start: datetime, plan: dict) -> None:
    print("== Assert I: tier-1 fires (fresh syslog drift window with violations) ==")
    sent_total = 0
    for i, run in enumerate(plan["runs"], 1):
        sent = run_simulator(mode="firmware-drift", eps=run["eps"],
                             duration=run["duration"], drift_after=run["drift_after"],
                             loop=True, label=f"I drift run {i}/{len(plan['runs'])}")
        sent_total += sent.get("syslog", 0)
    deadline = time.monotonic() + DRIFT_I_TIMEOUT_S
    hit, last = None, "no metrics response yet"
    while time.monotonic() < deadline and hit is None:
        status, body = http_json(f"{GATEWAY}/api/drift/metrics")
        if status == 200 and isinstance(body, dict):
            rows = body.get("metrics") or []
            last = f"{len(rows)} metric row(s), latest syslog window " \
                   f"{next((r['window_start'] for r in rows if r['fingerprint_id'] == SYSLOG_FP), 'none')}"
            for row in rows:
                if (row.get("fingerprint_id") == SYSLOG_FP
                        and _SEVERITY_RANK.get(row.get("severity"), -1) >= _SEVERITY_RANK["minor"]
                        and (row.get("violation_rate") or 0) > 0
                        and _parse_ts(row.get("window_start")) > run_start):
                    hit = row
                    break
        if hit is None:
            time.sleep(POLL_INTERVAL_S)
    if hit is None:
        check("I tier-1 fires", False,
              f"no syslog metrics row with severity>=minor and violation_rate>0 "
              f"within {DRIFT_I_TIMEOUT_S:.0f}s (last poll: {last})")
        return
    runs_desc = "; ".join(f"eps={r['eps']} drift-after={r['drift_after']} "
                          f"duration={r['duration']}s" for r in plan["runs"])
    check("I tier-1 fires", True,
          f"syslog field {hit['field']!r} window {hit['window_start']}: "
          f"severity={hit['severity']} violation_rate={hit['violation_rate']:.3f} "
          f"null_rate={(hit['null_rate'] or 0):.3f} events_count={hit['events_count']} "
          f"(tuned drift run(s): {runs_desc}; {sent_total} syslog lines sent; "
          f"predicted J-window violation {plan['j_violation']:.3f})")


def _wait_rule_quarantined(timeout_s: float) -> dict | None:
    """Poll GET /api/rules/syslog until the ACTIVE version's quarantined_fields
    contains the SRC mapping's target."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status, body = http_json(f"{GATEWAY}/api/rules/{SYSLOG_FP}")
        if status == 200 and isinstance(body, dict):
            for rule in body.get("rules") or []:
                if rule.get("status") == "active":
                    if QUARANTINE_FIELD in (rule.get("quarantined_fields") or []):
                        return rule
                    break  # active version exists, field not quarantined yet
        time.sleep(POLL_INTERVAL_S)
    return None


def assert_j_quarantine(run_start: datetime) -> None:
    print("== Assert J: moderate drift quarantines src_endpoint.ip, value preserved ==")
    quarantined = _wait_rule_quarantined(DRIFT_J_TIMEOUT_S)
    if quarantined is None:
        check("J quarantine + values preserved", False,
              f"active syslog rule never listed {QUARANTINE_FIELD} in "
              f"quarantined_fields within {DRIFT_J_TIMEOUT_S:.0f}s")
        return
    audit = audit_after(SYSLOG_FP, "field_quarantined", actor="drift", after=run_start)
    if audit is None:
        check("J quarantine + values preserved", False,
              f"quarantined_fields lists {QUARANTINE_FIELD} but no fresh "
              f"field_quarantined audit row with actor=drift")
        return
    quarantine_ts = _parse_ts(audit.get("ts"))
    # The pipeline honors quarantine on the next rule refresh (<= 2 s); the
    # margin plus a short steady probe supplies post-quarantine parses.
    time.sleep(RULE_REFRESH_MARGIN_S)
    run_simulator(label="J probe run (steady)", **PROBE_RUN)
    event = wait_parsed_event(quarantine_ts, _j_event_ok, DRIFT_J_TIMEOUT_S)
    if event is None:
        check("J quarantine + values preserved", False,
              f"no parsed syslog event after the quarantine audit ({audit.get('ts')}) "
              f"carries unmapped.SRC with src_endpoint.ip absent")
        return
    ocsf = event["ocsf"]
    check("J quarantine + values preserved", True,
          f"quarantined_fields=['{QUARANTINE_FIELD}'] on v{quarantined['version']} "
          f"(audit field_quarantined actor=drift at {audit.get('ts')}); parsed event "
          f"{event['event_id']} @ {event['parsed_at']} preserves SRC value "
          f"{ocsf['unmapped']['SRC']!r} under ocsf.unmapped.SRC with src_endpoint.ip absent")


def assert_k_severe(run_start: datetime, active: dict, pre_samples: int) -> None:
    print("== Assert K: severe -> rule deactivated -> re-onboard -> human restore ==")
    problems: list[str] = []
    parts: list[str] = []
    run_simulator(mode="firmware-drift", label="K-maker run (post-quarantine null flood)",
                  loop=True, **K_MAKER)

    deadline = time.monotonic() + DRIFT_K_TIMEOUT_S
    absent = False
    while time.monotonic() < deadline:
        # Only a SUCCESSFUL listing may prove absence (active_rule_fingerprints
        # degrades to an empty set on fetch errors — a hiccup must not
        # false-pass this check).
        status, body = http_json(f"{GATEWAY}/api/rules?status=active")
        if status == 200 and isinstance(body, dict):
            fps = {r.get("fingerprint_id") for r in body.get("rules") or []}
            if SYSLOG_FP not in fps:
                absent = True
                break
        time.sleep(POLL_INTERVAL_S)
    if absent:
        parts.append("syslog absent from /api/rules?status=active")
    else:
        problems.append("syslog never left the active rules within "
                        f"{DRIFT_K_TIMEOUT_S:.0f}s")

    audit = audit_after(SYSLOG_FP, "rule_deactivated", actor="drift", after=run_start,
                        want={"rule_id": active["id"]})
    if audit:
        parts.append(f"audit rule_deactivated actor=drift rule_id={active['id']} "
                     f"({(audit.get('detail') or {}).get('window_start')})")
    else:
        problems.append("no fresh rule_deactivated audit row actor=drift "
                        f"rule_id={active['id']}")

    # Seed a few syslog lines NOW that the rule is provably down: the
    # K-maker's own tail is a race (the simulator exits seconds before the
    # deactivating scan, so its last rows may all parse while the rule is
    # still active), but any line arriving after the deactivation is
    # unparsed and captured as an onboarding sample — the re-entry signal.
    run_simulator(label="K sample seeder (steady, rule down)",
                  eps="8", duration="4")

    samples = pre_samples
    deadline = time.monotonic() + DRIFT_K_TIMEOUT_S
    while time.monotonic() < deadline:
        samples = sample_count(SYSLOG_FP)
        if samples > pre_samples:
            break
        time.sleep(POLL_INTERVAL_S)
    if samples > pre_samples:
        parts.append(f"onboarding re-entry: sample_count {pre_samples}->{samples}")
    else:
        problems.append(f"sample_count never grew from {pre_samples}")

    # Freeze enforcement before the human restore: severe windows are
    # permanent rows of the version's view and the loop re-evaluates the whole
    # view every scan, so a live drift service would re-deactivate the
    # restored rule within one poll (verified live). Drift restarts after the
    # M3 block finishes restoring state.
    compose("stop", "drift", timeout=120)
    status, body = http_post_json(f"{GATEWAY}/api/rules/{active['id']}/reactivate",
                                  {"actor": "smoke", "reason": "M3 smoke: human restore"})
    if status == 200 and isinstance(body, dict) and body.get("status") == "active":
        parts.append(f"reactivate rule_id={active['id']} -> active (drift paused)")
    else:
        problems.append(f"reactivate rule_id={active['id']} -> {status}: {body!r}")
    restored = active_rule(SYSLOG_FP)
    if restored is not None and restored.get("id") == active["id"]:
        parts.append(f"active again: id={restored['id']} v{restored['version']}")
    else:
        problems.append(f"active syslog rule after restore: {restored!r}")
    reactivated = audit_after(SYSLOG_FP, "rule_reactivated", after=run_start,
                              want={"rule_id": active["id"]})
    if reactivated:
        parts.append(f"audit rule_reactivated rule_id={active['id']}")
    else:
        problems.append("no fresh rule_reactivated audit row "
                        f"rule_id={active['id']}")
    check("K severe -> deactivate -> re-onboard -> human restore", not problems,
          "; ".join(parts) + ("" if not problems else
                              "; PROBLEMS: " + "; ".join(problems)))


def assert_l_unquarantine(run_start: datetime) -> None:
    print("== Assert L: human un-quarantine re-enables the mapping ==")
    status, body = http_post_json(f"{GATEWAY}/api/rules/{SYSLOG_FP}/unquarantine",
                                  {"field": QUARANTINE_FIELD, "actor": "smoke"})
    if status != 200 or not isinstance(body, dict):
        check("L human un-quarantine", False,
              f"POST unquarantine -> {status}: {body!r}")
        return
    fields = body.get("quarantined_fields")
    audit = audit_after(SYSLOG_FP, "field_unquarantined", after=run_start,
                        want={"field": QUARANTINE_FIELD})
    if fields != [] or audit is None:
        check("L human un-quarantine", False,
              f"quarantined_fields={fields!r} (want []), "
              f"audit field_unquarantined={'present' if audit else 'MISSING'}")
        return
    unquarantine_ts = _parse_ts(audit.get("ts"))
    # Clean lines flush the quarantined-parses out; once the pipeline has the
    # un-quarantined rule (<= 2 s refresh), parses map src_endpoint.ip again.
    run_simulator(label="L flush run (steady)", **FLUSH_RUN)
    event = wait_parsed_event(unquarantine_ts, _l_event_ok, DRIFT_L_TIMEOUT_S)
    if event is None:
        check("L human un-quarantine", False,
              f"no parsed syslog event after the un-quarantine ({audit.get('ts')}) "
              f"maps src_endpoint.ip again")
        return
    src_ip = event["ocsf"]["src_endpoint"]["ip"]
    check("L human un-quarantine", True,
          f"POST unquarantine -> 200 quarantined_fields=[] (audit field_unquarantined "
          f"actor=smoke at {audit.get('ts')}); next clean parse {event['event_id']} @ "
          f"{event['parsed_at']} maps src_endpoint.ip={src_ip!r}")


def restore_syslog_rule(v1: dict) -> None:
    """Version-bump dance (restoration, not an assert): severe/null windows are
    permanent rows of v1's current view, so v1 can never again survive a drift
    scan. Mint a successor version WITHOUT the SRC mapping (its candidate gate
    is corruption-proof: corruption only ever touches SRC), approve it — the M2
    backlog sweep then re-parses and supersedes EVERY v1 row under the new
    version, emptying v1's drift view — deactivate the successor, and
    reactivate v1: active again, empty view, no severe findings possible. The
    stats current view keeps every row parsed (B's precondition), and the next
    smoke run's I-L block replays the whole cycle on v1."""
    print("== M3 restore: version-bump dance (clears v1's poisoned drift view) ==")
    failures: list[str] = []
    lines = read_corpus_lines(SYSLOG_CORPUS)
    report = validate_local_rule(SYSLOG_FP, SYSLOG_NO_SRC_RULE, lines)
    if not report.passed:
        failures.append(f"local gate: {report.checks}")
    rule_id = version = None
    if report.passed:
        status, body = post_manual_candidate(SYSLOG_FP, SYSLOG_NO_SRC_RULE)
        if status == 201 and isinstance(body, dict) and "rule_id" in body:
            rule_id, version = body["rule_id"], body.get("version")
        else:
            failures.append(f"manual candidate -> {status}: {body!r}")
    if rule_id is not None:
        status, body = http_post_json(
            f"{GATEWAY}/api/rules/{SYSLOG_FP}/candidates/{rule_id}/approve",
            {"actor": "smoke", "reason": "M3 smoke restore"})
        if status != 200:
            failures.append(f"approve v{version} -> {status}: {body!r}")
    if not failures and version is not None:
        reparse = wait_reparse_complete(SYSLOG_FP, version, REPARSE_TIMEOUT_S)
        if reparse is None:
            failures.append(f"no reparse_complete v{version} within {REPARSE_TIMEOUT_S:.0f}s")
        else:
            print(f"  sweep v{version}: inserted={reparse.get('inserted')} "
                  f"superseded={reparse.get('superseded')} (v1 drift view now empty)")
    if not failures:
        status, body = http_post_json(f"{GATEWAY}/api/rules/{SYSLOG_FP}/deactivate",
                                      {"actor": "smoke", "reason": "M3 smoke restore"})
        if status != 200:
            failures.append(f"deactivate successor -> {status}: {body!r}")
    if not failures:
        status, body = http_post_json(f"{GATEWAY}/api/rules/{v1['id']}/reactivate",
                                      {"actor": "smoke", "reason": "M3 smoke restore"})
        if status != 200:
            failures.append(f"reactivate v1 id={v1['id']} -> {status}: {body!r}")
    started = compose("start", "drift", timeout=120)
    if started.returncode != 0:
        failures.append(f"compose start drift failed: {started.stderr.strip()[:120]}")
    if failures:
        sys.exit("FATAL: M3 restoration dance failed: " + "; ".join(failures))
    left = syslog_view_count(v1["version"])
    print(f"  restore complete: successor v{version} deactivated (holds the superseded "
          f"backlog), seed rule id={v1['id']} active with a {left}-row drift view; "
          f"drift service restarted")


def wait_quiet(window_s: float = 4.0, timeout_s: float = 45.0) -> int:
    """Wait until raw_events stops moving, then return its count.

    The delta base is taken only when the DB is quiescent, so stray traffic
    (e.g. the quickstart's `--profile sim` one-shot still draining) cannot be
    charged to this run's asserts.
    """
    deadline = time.monotonic() + timeout_s
    last = db_count("SELECT count(*) FROM raw_events")
    last_change = time.monotonic()
    while time.monotonic() < deadline:
        time.sleep(2.0)
        current = db_count("SELECT count(*) FROM raw_events")
        if current != last:
            last, last_change = current, time.monotonic()
        elif time.monotonic() - last_change >= window_s:
            return current
    return last


def main() -> int:
    # M3 demo knobs (Task 12 Step 1) — exported BEFORE compose up so the drift
    # container is created with demo-scale windows (30 rows; compose
    # passthrough verified in Task 4). The window count is load-bearing for
    # the drift-run tuning below.
    os.environ["ULPF_DRIFT_WINDOW_COUNT"] = DRIFT_WINDOW_COUNT
    os.environ["ULPF_DRIFT_WINDOW_TIME_S"] = DRIFT_WINDOW_TIME_S
    # Sample-capture headroom (observed live in the Task 12 gate): the
    # accumulating DB saturates the 200/fingerprint cap, after which a
    # drift-deactivated fingerprint cannot accumulate onboarding samples and
    # K's re-entry signal (sample_count grows) is unobservable. 2000 leaves
    # headroom for many accumulating runs; the code default stays 200.
    os.environ["ULPF_SAMPLE_CAPTURE_CAP"] = "2000"
    print(f"ULPF smoke (M1 A-E + M2 F-H + M3 I-L) - {time.strftime('%Y-%m-%d %H:%M:%S')}")
    step1_up()

    # M3 block FIRST (Task 12 Steps 2-5): the drift demo needs the syslog
    # baseline to arm DURING the firmware-drift run (the establishing 10th
    # window must itself be the moderate one — see the module header), so it
    # runs before the A-H steady traffic can pre-arm a clean baseline.
    run_start = datetime.now(UTC)
    active = active_rule(SYSLOG_FP)
    if active is None:
        sys.exit("FATAL: no active syslog rule at the M3 block start")
    corpus_lines = len(read_corpus_lines(SYSLOG_CORPUS))
    offset = syslog_view_count(active["version"]) % 30
    plan = tune_drift_run(offset, corpus_lines)
    runs_desc = " then ".join(
        f"eps={r['eps']}/after={r['drift_after']}/dur={r['duration']}s" for r in plan["runs"])
    print(f"  syslog seed rule id={active['id']} v{active['version']}; drift view "
          f"offset={offset} -> tuned drift run(s): {runs_desc} "
          f"(predicted J-window violation {plan['j_violation']:.3f} "
          f"({plan['j_nulls']} nulls), establishing window "
          f"{plan['est_violation']:.3f})")
    pre_samples = sample_count(SYSLOG_FP)

    assert_i_tier1(run_start, plan)
    assert_j_quarantine(run_start)
    assert_k_severe(run_start, active, pre_samples)
    assert_l_unquarantine(run_start)
    restore_syslog_rule(active)

    if M3_ONLY:
        failed = [name for name, ok, _ in results if not ok]
        print(f"\nSMOKE RESULT (M3 I-L only): {'PASS' if not failed else 'FAIL'} "
              f"({len(results) - len(failed)}/{len(results)} checks)"
              + (f" failed: {', '.join(failed)}" if failed else ""))
        return 0 if not failed else 1

    print("== Snapshot before (delta base) ==")
    before_raw = wait_quiet()
    before_norm = db_count("SELECT count(*) FROM normalized_events")
    before_fps = stats_by_fingerprint()
    print(f"  raw_events={before_raw} normalized_events={before_norm} "
          f"fingerprints={len(before_fps)}")

    sent = run_simulator(label="Step 2 (steady)")
    print("  " + ", ".join(f"{name}={n}" for name, n in sorted(sent.items())))

    drained, raw_delta, norm_delta = wait_drain(before_raw, before_norm, sent["total"])
    if not drained:
        print(f"[FAIL] drain: pipeline did not drain within {DRAIN_TIMEOUT_S:.0f}s "
              f"(raw delta={raw_delta}, normalized delta={norm_delta}, sent={sent['total']})")
        return 1
    print(f"  drained: raw delta={raw_delta}, normalized delta={norm_delta}")

    assert_a(before_raw, sent["total"])
    assert_b(before_fps)
    assert_c()
    assert_d_replay()
    assert_e_chain()

    # M2 (Task 12): the onboarding hero loop. Fingerprints are computed
    # host-side with the pipeline's own function; rules are approved through
    # the gateway and the R11 backlog sweep is verified by per-run deltas.
    newapp_lines = read_corpus_lines(NEWAPP_CORPUS)
    fp = corpus_fingerprint(newapp_lines, "newapp")
    assert_f_hero(newapp_lines, fp)

    zenwall_lines = ensure_zenwall_corpus()
    zfp = corpus_fingerprint(zenwall_lines, "zenwall")
    assert_g_manual(zenwall_lines, zfp)

    assert_h(fp, zfp)

    failed = [name for name, ok, _ in results if not ok]
    print(f"\nSMOKE RESULT: {'PASS' if not failed else 'FAIL'} "
          f"({len(results) - len(failed)}/{len(results)} checks)"
          + (f" failed: {', '.join(failed)}" if failed else ""))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
