#!/usr/bin/env python3
"""ULPF M1 acceptance smoke (Task 12, spec section 15) — the milestone exit gate.

End-to-end against the live compose stack: drives the simulator over the golden
corpora, then verifies lossless ingest, the parsed/unparsed split, raw
traceability, forced replay idempotency (consumer-group delete + pipeline
restart), and independently re-verifies EVERY raw_batches merkle root plus the
per-partition hash chain linkage.

Host requirements (Python 3.13 tested): confluent-kafka~=2.6, psycopg[binary].
Everything else is stdlib (urllib for HTTP, subprocess for docker compose).
Docker commands run from deploy/; the DB is NOT reset — every count assertion
is delta-based (snapshot before, diff after), so re-runs accumulate.

Usage:  python scripts/smoke.py          (from the repo root)
Exit:   0 all checks PASS, 1 any FAIL.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import psycopg

# pipeline.hashchain lives at services/pipeline (package dir named `pipeline`);
# services/ on sys.path is what makes `import pipeline` resolve.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services"))
from pipeline.hashchain import GENESIS_PREV_HASH, merkle_root

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
DSN = "postgresql://postgres:postgres@localhost:5433/ulpf"  # admin, host port (5433: compose publish; 5432 often owned by a native Postgres)
GATEWAY = "http://localhost:8000"
WEB = "http://localhost:3000"

SIM_EPS = "25"
SIM_DURATION = "20"  # ~500 events: corpora total 57 lines -> several loops
SEEDED_FPS = ("cef_paloalto", "cef_ciscoasa", "cef_fortigate", "syslog", "json")
TRACE_SAMPLE = 20

BUILD_TIMEOUT_S = 900
READY_TIMEOUT_S = 240
SIM_TIMEOUT_S = 300
DRAIN_TIMEOUT_S = 150
LAG_TIMEOUT_S = 180
POLL_INTERVAL_S = 2.0

_SIM_LINE = re.compile(r"^(\w+) sent=(\d+)$", re.MULTILINE)
_LAG_LINE = re.compile(r"^TOTAL-LAG\s+(\S+)\s*$", re.MULTILINE)

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str) -> bool:
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")
    return ok


def compose(*args: str, timeout: float = 300) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", *args], cwd=DEPLOY, capture_output=True,
        text=True, timeout=timeout, check=False,
    )


def http_get(url: str, timeout: float = 10) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, b""


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
    print("== Step 1: docker compose up -d --build + health wait ==")
    out = compose("up", "-d", "--build", timeout=BUILD_TIMEOUT_S)
    if out.returncode != 0:
        print(out.stdout[-2000:])
        print(out.stderr[-2000:])
        sys.exit("FATAL: compose up failed; cannot run the smoke.")
    ok_gw = wait_http_ready(f"{GATEWAY}/api/stats", "gateway", READY_TIMEOUT_S)
    ok_web = wait_http_ready(f"{WEB}/", "web", READY_TIMEOUT_S)
    ok_group = wait_group_present(READY_TIMEOUT_S)
    if not (ok_gw and ok_web and ok_group):
        sys.exit("FATAL: stack not ready (gateway/web/kafka group 'pipeline').")


def run_simulator() -> dict[str, int]:
    print(f"== Step 2: simulator --eps {SIM_EPS} --duration {SIM_DURATION} ==")
    out = compose("run", "--rm", "-T", "simulator",
                  "--eps", SIM_EPS, "--duration", SIM_DURATION, timeout=SIM_TIMEOUT_S)
    sent = {name: int(n) for name, n in _SIM_LINE.findall(out.stdout)}
    if out.returncode != 0 or "total" not in sent:
        print("stdout:", out.stdout[-2000:])
        print("stderr:", out.stderr[-2000:])
        sys.exit("FATAL: simulator run failed or stdout contract broken.")
    corpora_total = sum(n for name, n in sent.items() if name != "total")
    missing = {"acmegw", "cef", "json", "syslog"} - set(sent)
    if missing or corpora_total != sent["total"]:
        sys.exit(f"FATAL: simulator stdout contract broken: {sent} (missing={missing})")
    return sent


def assert_a(before_raw: int, total_sent: int) -> None:
    print("== Assert A: lossless (raw_events delta == sent) ==")
    raw_after = db_count("SELECT count(*) FROM raw_events")
    delta = raw_after - before_raw
    check("A lossless", delta == total_sent,
          f"sent={total_sent} raw_events delta={delta} (before={before_raw} after={raw_after})")


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
    for fp, row in autos.items():
        if row["parsed"] != 0:
            ok = False
            problems.append(f"{fp}: parsed={row['parsed']} (must be 0)")
    if not autos or auto_delta == 0:
        ok = False
        problems.append("no auto_* fingerprint saw traffic (AcmeGW unparsed path unexercised)")
    total_sent_b = seeded_delta + auto_delta
    details.append(f"    seeded delta={seeded_delta}, auto delta={auto_delta}, sum={total_sent_b}")
    check("B parsed split", ok, "; ".join(problems) if problems else
          f"5 seeded fingerprints fully parsed, auto_* fully unparsed{details[0]}\n{details[1]}")


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


def assert_d_replay() -> None:
    print("== Assert D: forced replay (group delete + pipeline restart) ==")
    pre_raw = db_count("SELECT count(*) FROM raw_events")
    pre_batches = db_count("SELECT count(*) FROM raw_batches")
    pre_fps = stats_by_fingerprint()

    # Order matters: the pipeline is stopped BEFORE the group delete. Deleted
    # while running, the live consumer's auto-rejoin recreates the group and
    # re-commits its offsets within seconds, so a restart afterwards would have
    # nothing to redeliver (vacuous replay, observed as raw_batches unchanged).
    stop = compose("stop", "pipeline", timeout=180)
    if stop.returncode != 0:
        check("D replay idempotency", False,
              f"compose stop pipeline failed: {stop.stderr.strip()[:200]}")
        return
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:  # consumer must be fully out of the group
        out = rpk("group", "describe", "pipeline")
        if out.returncode != 0 or re.search(r"^MEMBERS\s+0\s*$", out.stdout, re.MULTILINE):
            break
        time.sleep(POLL_INTERVAL_S)
    print("  pipeline stopped; consumer has left the group")

    listing = rpk("group", "list")
    group_present = listing.returncode == 0 and any(
        line.split()[-1:] == ["pipeline"]
        for line in listing.stdout.splitlines() if line.split())
    if not group_present:
        check("D replay idempotency", False,
              f"kafka group 'pipeline' absent before delete (replay would be vacuous): "
              f"{listing.stdout.strip()!r}")
        return
    delete = rpk("group", "delete", "pipeline")
    if delete.returncode != 0:
        check("D replay idempotency", False,
              f"rpk group delete failed rc={delete.returncode}: {delete.stderr.strip()[:200]}")
        return
    print("  group 'pipeline' deleted (committed offsets dropped); starting pipeline")
    start = compose("start", "pipeline", timeout=180)
    if start.returncode != 0:
        check("D replay idempotency", False, f"compose start pipeline failed: "
              f"{start.stderr.strip()[:200]}")
        return
    lag_ok, lag_detail = wait_group_lag_zero(LAG_TIMEOUT_S)
    if not lag_ok:
        check("D replay idempotency", False, f"group lag never reached 0: {lag_detail}")
        return
    print(f"  replay drained ({lag_detail})")

    post_raw = db_count("SELECT count(*) FROM raw_events")
    post_batches = db_count("SELECT count(*) FROM raw_batches")
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
    print(f"ULPF M1 smoke - {time.strftime('%Y-%m-%d %H:%M:%S')}")
    step1_up()

    print("== Snapshot before (delta base) ==")
    before_raw = wait_quiet()
    before_norm = db_count("SELECT count(*) FROM normalized_events")
    before_fps = stats_by_fingerprint()
    print(f"  raw_events={before_raw} normalized_events={before_norm} "
          f"fingerprints={len(before_fps)}")

    sent = run_simulator()
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

    failed = [name for name, ok, _ in results if not ok]
    print(f"\nSMOKE RESULT: {'PASS' if not failed else 'FAIL'} "
          f"({len(results) - len(failed)}/{len(results)} checks)"
          + (f" failed: {', '.join(failed)}" if failed else ""))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
