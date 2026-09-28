# simulator/tests/test_drift.py — firmware-drift mode (T11): deterministic
# escalating syslog corruption on the wire. R-P3 selection (seed = line index,
# strict <), R-P9 variant split (index % 3). Pure-function pins first, then
# run()/main() wiring via the fake senders from test_simulate (imported, not
# duplicated — that file must stay byte-identical per the M2 regression pins).
import math
import re

import simulator.tests.test_simulate as ts
from simulator.simulate import (
    ESCALATION_SPAN_FLOOR_S,
    _parse_args,
    corrupt_syslog,
    drift_phase,
    escalation_span,
    main,
)
from simulator.tests.test_simulate import Corpus, FakeHttp, FakeUdp

# --- the R-P3 ruling restated verbatim (independent of the implementation) -------

def selector(index):
    """R-P3: (line_index * 2654435761 % 1000) / 1000 — per-line value in [0, 1)."""
    return (index * 2654435761 % 1000) / 1000


def syslog_line(i):
    return (f"Aug 27 14:32:0{i} fw01 kernel: IPTABLES-DROP: IN=eth0 OUT= "
            f"SRC=203.0.113.{i} DST=192.168.1.{i} LEN=60 PROTO=TCP SPT=5142{i} "
            f"DPT=22 FLAGS=SYN")


def renamed(line):
    """R-P9 variant A (index % 3 == 0): field SRC renamed to SRCADDR, value kept."""
    return line.replace("SRC=", "SRCADDR=", 1)


def poisoned(line):
    """R-P9 variant B (other indices): the SRC value becomes an invalid token."""
    return re.sub(r"\bSRC=\S*", "SRC=uplink-trust-0x4f", line, count=1)


# --- corrupt_syslog: R-P3 selection + R-P9 variants -------------------------------

def test_p3_selection_covers_a_uniform_fraction_of_indices():
    # 2654435761 % 1000 == 761 is coprime with 1000, so the selector is a
    # permutation of k/1000: phase p selects exactly p of any 1000 consecutive
    # indices — the escalation is smooth and phase 1.0 selects EVERYTHING.
    for phase in (0.1, 0.25, 0.5, 0.9, 1.0):
        selected = sum(1 for i in range(1000) if selector(i) < phase)
        assert selected == int(phase * 1000)


def test_phase_zero_leaves_lines_unchanged():
    for i in range(15):
        assert corrupt_syslog(syslog_line(i), i, 0.0) == syslog_line(i)


def test_phase_one_corrupts_every_line_with_exact_variant_split():
    lines = [syslog_line(i) for i in range(15)]
    outs = [corrupt_syslog(line, i, 1.0) for i, line in enumerate(lines)]
    assert all(out != line for out, line in zip(outs, lines))  # every line hit
    renames = 0
    for i, (line, out) in enumerate(zip(lines, outs)):
        if i % 3 == 0:
            renames += 1
            assert out == renamed(line)   # SRC -> SRCADDR (null-rate spike)
        else:
            assert out == poisoned(line)  # SRC=uplink-trust-0x4f (tier-1)
    assert renames == 5  # exact 1/3 rename : 2/3 value-replace over 15 lines


def test_phase_one_variants_pinned_as_full_literals():
    # Independent of any helper: the two variants, spelled out byte for byte.
    assert corrupt_syslog(syslog_line(0), 0, 1.0) == (
        "Aug 27 14:32:00 fw01 kernel: IPTABLES-DROP: IN=eth0 OUT= "
        "SRCADDR=203.0.113.0 DST=192.168.1.0 LEN=60 PROTO=TCP SPT=51420 "
        "DPT=22 FLAGS=SYN")
    assert corrupt_syslog(syslog_line(1), 1, 1.0) == (
        "Aug 27 14:32:01 fw01 kernel: IPTABLES-DROP: IN=eth0 OUT= "
        "SRC=uplink-trust-0x4f DST=192.168.1.1 LEN=60 PROTO=TCP SPT=51421 "
        "DPT=22 FLAGS=SYN")


def test_line_without_src_passes_through_even_at_phase_one():
    bare = "Aug 27 14:32:07 fw01 sshd[1901]: Accepted publickey for root"
    for i in range(6):
        assert corrupt_syslog(bare, i, 1.0) == bare


def test_corrupt_syslog_is_deterministic():
    # same inputs -> same outputs, always: no RNG state anywhere.
    for phase in (0.0, 0.044, 0.283, 0.5, 0.761, 1.0):
        for i in range(30):
            line = syslog_line(i % 15)
            assert corrupt_syslog(line, i, phase) == corrupt_syslog(line, i, phase)


def test_p3_selection_is_strictly_less_than_phase():
    i = 4  # selector(4) == 0.044: the smallest positive selector below index 5
    line = syslog_line(i)
    boundary = selector(i)  # exactly the R-P3 value, computed the same way
    assert corrupt_syslog(line, i, boundary) == line  # equality -> NOT corrupted
    just_above = math.nextafter(boundary, 1.0)
    assert corrupt_syslog(line, i, just_above) == poisoned(line)  # any epsilon above


# --- escalation math (R-P3): phase only grows; span never divides by zero --------

def test_drift_phase_is_monotonic_and_clamped():
    for span in (1.0, 2.5, 55.0):
        phases = [drift_phase(t, span) for t in (0.0, 0.1, 0.3, span / 2, span, span + 5)]
        assert phases == sorted(phases)  # only grows with elapsed time
        assert phases[0] == 0.0
        assert phases[-1] == 1.0  # clamped once the escalation span has elapsed
        assert all(0.0 <= p <= 1.0 for p in phases)
    assert drift_phase(-1.0, 1.0) == 0.0  # pre-drift elapsed clamps to clean


def test_escalation_span_defaults_to_remaining_budget():
    assert escalation_span(60.0, 5.0) == 55.0  # duration - drift_after
    assert escalation_span(10.0, 0.0) == 10.0


def test_escalation_span_floors_when_drift_consumes_the_budget():
    assert escalation_span(10.0, 10.0) == ESCALATION_SPAN_FLOOR_S  # equal -> floor
    assert escalation_span(3.0, 9.0) == ESCALATION_SPAN_FLOOR_S  # past the budget
    assert ESCALATION_SPAN_FLOOR_S > 0
    assert drift_phase(0.5, escalation_span(10.0, 10.0)) == 0.5  # no ZeroDivision


# --- run(): drift wiring (clean before drift_after; only syslog mutates) ---------

def test_drift_clean_until_drift_after_and_byte_identical_to_steady():
    pristine = {"cef": ["c1", "c2"], "acmegw": ["a1"],
                "json": ["j1"], "syslog": [syslog_line(i) for i in range(4)]}
    drift_log, steady_log = [], []

    def corpora_for(log):
        return [Corpus(name=k, lines=list(v),
                       sender=FakeHttp(k, log, batch_size=100) if k == "json"
                       else FakeUdp(k, log))
                for k, v in pristine.items()]

    _sent_d, err_d = ts.do_run(corpora_for(drift_log), eps=100, duration=0.5,
                               drift_after=60.0)  # drift never due within the run
    _sent_s, err_s = ts.do_run(corpora_for(steady_log), eps=100, duration=0.5)
    assert err_d == err_s == 0
    assert drift_log == steady_log  # same wire content as steady, byte for byte
    assert [l for n, l in drift_log if n == "syslog"] == pristine["syslog"]


def test_drift_corrupts_only_syslog_after_the_boundary():
    pristine = {"cef": [f"c{i}" for i in range(6)],
                "acmegw": [f"a{i}" for i in range(6)],
                "json": [f"j{i}" for i in range(6)],
                "syslog": [syslog_line(i) for i in range(6)]}
    log = []
    corpora = [Corpus(name=k, lines=list(v),
                      sender=FakeHttp(k, log, batch_size=100) if k == "json"
                      else FakeUdp(k, log))
               for k, v in pristine.items()]
    sent, errors = ts.do_run(corpora, eps=30, duration=0.6, loop=True, drift_after=0.0)
    assert errors == 0
    assert sent["syslog"] >= 2  # enough sends to see the escalation
    # the other corpora stay byte-identical to their pristine files
    for k in ("cef", "acmegw", "json"):
        assert {l for n, l in log if n == k} <= set(pristine[k])
    # every mutated syslog line is exactly one of the two R-P9 variants
    variants = {renamed(l) if i % 3 == 0 else poisoned(l)
                for i, l in enumerate(pristine["syslog"])}
    syslog_out = [l for n, l in log if n == "syslog"]
    corrupted = [l for l in syslog_out if l not in pristine["syslog"]]
    assert corrupted  # drift did fire
    assert set(corrupted) <= variants
    assert renamed(syslog_line(0)) in corrupted  # selector(0)=0.0 < any phase>0
    assert poisoned(syslog_line(4)) in corrupted  # selector(4)=0.044, phase>0.1


def test_drift_boundary_is_respected_mid_pass():
    # SlowUdp spends 0.05s per send, so one pass straddles drift_after=0.09:
    # corruption is decided per send (send-start time), not per pass.
    log = []
    slow = ts.SlowUdp("syslog", log, 0.05)
    lines = [syslog_line(i) for i in range(6)]
    corpora = [Corpus("cef", ["c1"], FakeUdp("cef", log)),
               Corpus("syslog", lines, slow)]
    sent, errors = ts.do_run(corpora, eps=100, duration=1.0, drift_after=0.09)
    assert errors == 0
    assert sent == {"cef": 1, "syslog": 6}  # counts unchanged: content only mutates
    syslog_sends = [l for n, l in log if n == "syslog"]
    assert len(syslog_sends) == 6
    # decided at ~0.00s/~0.05s: before the boundary -> pristine
    assert syslog_sends[0] == lines[0]
    assert syslog_sends[1] == lines[1]
    # past the boundary but selector(i) > phase -> still pristine
    assert syslog_sends[2] == lines[2]  # selector(2)=0.522
    assert syslog_sends[3] == lines[3]  # selector(3)=0.283
    assert syslog_sends[5] == lines[5]  # selector(5)=0.805
    # decided at >=0.20s: phase >= 0.11 > selector(4)=0.044 -> P-9 value variant
    assert syslog_sends[4] == poisoned(lines[4])


# --- main(): --mode firmware-drift wiring + the M1 stdout contract ----------------

def wire(tmp_path, monkeypatch, contents):
    ts.make_corpora(tmp_path, contents)
    log = []

    def senders():
        return {k: (FakeHttp(k, log, batch_size=100) if k == "json" else FakeUdp(k, log))
                for k in contents}

    monkeypatch.setattr("simulator.simulate.default_senders", senders)
    return log


SIM_LINE = re.compile(r"^(\w+) sent=(\d+)$", re.MULTILINE)  # the M1 smoke regex


def test_main_firmware_drift_stdout_contract(tmp_path, capsys, monkeypatch):
    log = wire(tmp_path, monkeypatch,
               {"cef": "c1\nc2\n", "json": "j1\n",
                "syslog": "\n".join(syslog_line(i) for i in range(3)) + "\n"})
    rc = main(["--eps", "100", "--duration", "1", "--mode", "firmware-drift",
               "--drift-after", "60", "--corpora", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.strip().splitlines() == [
        "cef sent=2", "json sent=1", "syslog sent=3", "total sent=6"]
    matches = SIM_LINE.findall(out)  # still exactly one line per corpus + total
    assert ("syslog", "3") in matches and ("total", "6") in matches
    assert sum(1 for name, _ in matches if name == "syslog") == 1
    assert len(log) == 6  # counts unchanged: only line CONTENT may mutate


def test_main_firmware_drift_omits_newapp(tmp_path, capsys, monkeypatch):
    wire(tmp_path, monkeypatch, {"cef": "c1\n", "newapp": "n1\n"})
    rc = main(["--eps", "100", "--duration", "1", "--mode", "firmware-drift",
               "--corpora", str(tmp_path)])
    out = capsys.readouterr().out.strip().splitlines()
    assert rc == 0
    assert out == ["cef sent=1", "total sent=1"]  # steady corpus set: no newapp


def test_drift_after_flag_defaults_to_five_seconds():
    args = _parse_args(["--mode", "firmware-drift"])
    assert args.drift_after == 5.0
    args = _parse_args(["--mode", "firmware-drift", "--drift-after", "12.5"])
    assert args.drift_after == 12.5


def test_main_firmware_drift_default_after_keeps_short_run_clean(
        tmp_path, capsys, monkeypatch):
    log = wire(tmp_path, monkeypatch,
               {"syslog": "\n".join(syslog_line(i) for i in range(4)) + "\n"})
    rc = main(["--eps", "100", "--duration", "0.3", "--mode", "firmware-drift",
               "--corpora", str(tmp_path)])  # default --drift-after 5 > run length
    assert rc == 0
    assert [l for n, l in log] == [syslog_line(i) for i in range(4)]  # pristine


def test_main_two_identical_drift_runs_produce_identical_bytes(
        tmp_path, capsys, monkeypatch):
    outs, logs = [], []
    for _ in range(2):
        log = wire(tmp_path, monkeypatch,
                   {"cef": "c1\nc2\n", "json": "j1\n",
                    "syslog": "\n".join(syslog_line(i) for i in range(3)) + "\n"})
        rc = main(["--eps", "100", "--duration", "0.4", "--mode", "firmware-drift",
                   "--drift-after", "0", "--corpora", str(tmp_path)])
        assert rc == 0
        outs.append(capsys.readouterr().out)
        logs.append(log)
    assert outs[0] == outs[1]  # stdout bytes identical across runs
    assert logs[0] == logs[1]  # wire content identical too
    # index 0 (selector 0.0 < any positive phase) takes the rename variant;
    # indices 1-2 (selectors 0.761 / 0.522) stay pristine at these tiny phases
    assert [l for n, l in logs[0] if n == "syslog"] == [
        renamed(syslog_line(0)), syslog_line(1), syslog_line(2)]


def test_steady_modes_still_reject_no_drift_wiring(tmp_path, capsys, monkeypatch):
    # steady/new-appliance never mutate a line even if --drift-after is passed:
    # the flag is firmware-drift-only (mirrors --new-after being ignored).
    log = wire(tmp_path, monkeypatch,
               {"syslog": "\n".join(syslog_line(i) for i in range(3)) + "\n"})
    rc = main(["--eps", "100", "--duration", "0.3", "--drift-after", "0",
               "--corpora", str(tmp_path)])
    assert rc == 0
    assert [l for n, l in log] == [syslog_line(i) for i in range(3)]  # pristine
