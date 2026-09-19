# services/pipeline/tests/test_seed_rules.py — the activation gate for the
# hand-authored seed rules (spec §6.4, Task 8).
#
# Contract: every seed must validate against its OWN format's golden lines
# (the CEF corpus mixes three vendors — fingerprint_id picks each seed's own
# vendor lines, controller R8) before it may ever load; the unknown formats
# (auto_*: AcmeGW, Zenwall) must stay unseeded so they arrive 'unparsed' and
# remain M2's onboarding heroes. The runner is also pinned here: a broken seed
# exits without inserting anything, and inserts always carry the ON CONFLICT
# idempotency guard.
import pytest
from ulpf_core.fingerprint import fingerprint_id
from ulpf_core.parsing import OCSF_TARGETS, validate_rule_output

from pipeline import seed_rules

EXPECTED_SEED_IDS = {"cef_ciscoasa", "cef_fortigate", "cef_paloalto", "json", "syslog"}


def test_discovers_exactly_five_golden_seeds():
    seeds = seed_rules.discover_seeds()
    assert set(seeds) == EXPECTED_SEED_IDS
    for seed in seeds.values():
        assert seed.rule.version == 1
        assert seed.rule.provenance == "human"


@pytest.mark.parametrize("fp_id", sorted(EXPECTED_SEED_IDS))
def test_seed_validates_against_its_own_corpus_lines(fp_id):
    seed = seed_rules.discover_seeds()[fp_id]
    samples = seed_rules.samples_for(seed)
    assert samples, (
        f"no {fp_id} lines in {seed.corpus}: the corpus or fingerprint_id "
        "drifted from the function's output (R8) — never seed a guessed id"
    )
    assert validate_rule_output(seed.rule, samples) == []


def test_unknown_formats_are_not_seeded():
    # AcmeGW + Zenwall fingerprint to auto_* shape ids: no seed may claim them.
    seeded = set(seed_rules.discover_seeds())
    for corpus in ("raw_logs_acmegw.txt", "raw_logs_zenwall.txt"):
        lines = seed_rules.corpus_lines(corpus)
        assert lines
        ids = {fingerprint_id(line) for line in lines}
        assert ids
        assert all(fid.startswith("auto_") for fid in ids)
        assert not (ids & seeded), f"{corpus} must stay unseeded (M2 onboarding hero)"


def test_syslog_seed_leaves_flags_unmapped():
    # The legacy FLAGS->action mapping was wrong (action is a verdict, not a
    # TCP flag) — the seed maps SRC/DST/SPT/DPT only.
    rule = seed_rules.discover_seeds()["syslog"].rule
    sources = {m.source_field for m in rule.mappings}
    assert {"SRC", "DST", "SPT", "DPT"} <= sources
    assert "FLAGS" not in sources


def test_all_mappings_within_ocsf_allow_list():
    # With no samples, validate_rule_output still checks pattern caps, compile
    # and the mapping allow-list — so an empty-sample pass pins the allow-list.
    for seed in seed_rules.discover_seeds().values():
        assert validate_rule_output(seed.rule, []) == []
        for mapping in seed.rule.mappings:
            assert mapping.ocsf_path in OCSF_TARGETS


class RecordingConn:
    """Fake psycopg connection: records execute() calls, never touches a DB."""

    def __init__(self):
        self.executed = []

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    rowcount = 1

    def commit(self):
        pass


def test_seed_database_inserts_with_idempotency_guard():
    conn = RecordingConn()
    assert seed_rules.seed_database(conn) == 0
    inserts = [sql for sql, _ in conn.executed]
    assert len(inserts) == len(EXPECTED_SEED_IDS)
    for sql in inserts:
        assert "ON CONFLICT (fingerprint_id, version) DO NOTHING" in sql
        assert "status" in sql and "'active'" in sql
        assert "'human'" in sql and "'seed'" in sql
    # mappings ride as JSONB: the Json adapter wraps plain dicts (json-serializable),
    # never pydantic models
    params = next(p for _, p in conn.executed if p[0] == "cef_paloalto")
    assert isinstance(params[3].obj, list) and isinstance(params[3].obj[0], dict)


def test_broken_seed_never_inserts(monkeypatch, caplog):
    seeds = seed_rules.discover_seeds()
    broken = dict(seeds)
    from ulpf_core.models import Mapping, Rule
    broken["cef_paloalto"] = seed_rules.Seed(
        rule=Rule(
            fingerprint_id="cef_paloalto", version=1,
            pattern="(?P<extension>[",  # does not compile
            mappings=[Mapping(source_field="src", ocsf_path="src_endpoint.ip")],
            provenance="human",
        ),
        corpus="raw_logs_cef.txt",
    )
    monkeypatch.setattr(seed_rules, "discover_seeds", lambda: broken)
    conn = RecordingConn()

    with caplog.at_level("ERROR", logger="pipeline.seed_rules"):
        assert seed_rules.seed_database(conn) == 1
    assert conn.executed == []  # nothing loaded — not even the healthy seeds
    assert "cef_paloalto" in caplog.text  # the failure names the broken rule
