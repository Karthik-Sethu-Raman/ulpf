# services/pipeline/seed_rules.py — idempotent loader for the hand-authored
# seed rules (Task 8). Runnable one-shot: `python -m pipeline.seed_rules`.
#
# Order of operations is the safety story (spec §6.4):
#   1. load every seeds/*.json into a Rule;
#   2. validate ALL of them (validate_rule_output) against their OWN format's
#      golden corpus lines — each seed JSON names its corpus, and the corpus
#      lines are grouped by fingerprint_id(line) so a mixed corpus (the CEF
#      file carries three vendors) only ever proves a seed against its own
#      vendor (controller R8: ids come from the function, never the plan);
#   3. only if every seed passes, INSERT them — ON CONFLICT (fingerprint_id,
#      version) DO NOTHING, status='active', provenance='human',
#      created_by='seed', activated_at=now().
# A broken seed therefore exits 1 naming the rule and loads NOTHING, and a
# re-run over an already-seeded DB inserts nothing and exits 0 (idempotent).
#
# The connection is the ADMIN url (ADMIN_DATABASE_URL, same env the migrate
# service uses): pipeline_role is deliberately SELECT-only on rules, so the
# one-shot seed service cannot run as the pipeline (controller R18). psycopg
# is imported lazily so the validation half is unit-testable without a DB.
from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from ulpf_core.fingerprint import fingerprint_id
from ulpf_core.models import Mapping, Rule
from ulpf_core.parsing import validate_rule_output

log = logging.getLogger("pipeline.seed_rules")

SEEDS_DIR = Path(__file__).resolve().parent / "seeds"

SEED_VERSION = 1
SEED_PROVENANCE = "human"
SEED_CREATED_BY = "seed"

# One statement, every seed: the (fingerprint_id, version) unique constraint
# makes a re-run a no-op, and the column set is exactly the R18 contract.
_INSERT_SQL = (
    "INSERT INTO rules (fingerprint_id, version, pattern, mappings, "
    "status, provenance, created_by, activated_at) "
    "VALUES (%s, %s, %s, %s, 'active', 'human', 'seed', now()) "
    "ON CONFLICT (fingerprint_id, version) DO NOTHING"
)


class SeedError(Exception):
    """A seed file could not be loaded — the runner must exit 1, never load."""


@dataclass(frozen=True)
class Seed:
    """One seed rule plus the golden corpus it must prove itself against."""

    rule: Rule
    corpus: str


def golden_dir() -> Path:
    """Where the golden corpora live: ULPF_GOLDEN_DIR if set (the seed
    container), else the repo checkout's libs/ulpf-core test data."""
    env = os.environ.get("ULPF_GOLDEN_DIR")
    if env:
        return Path(env)
    # services/pipeline/seed_rules.py -> parents[2] is the repo root
    return Path(__file__).resolve().parents[2] / "libs" / "ulpf-core" / "tests" / "data" / "golden"


def corpus_lines(corpus: str) -> list[str]:
    """Non-blank lines of one golden corpus file."""
    path = golden_dir() / corpus
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SeedError(f"corpus {corpus!r} unreadable at {path}: {exc}") from exc
    return [line.strip() for line in text.splitlines() if line.strip()]


def load_seed(path: Path) -> Seed:
    """One seed JSON -> Seed; any malformation is a SeedError naming the file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        rule = Rule(
            fingerprint_id=data["fingerprint_id"],
            version=SEED_VERSION,
            pattern=data["pattern"],
            mappings=[Mapping(**m) for m in data["mappings"]],
            provenance=SEED_PROVENANCE,
        )
        corpus = data["corpus"]
    except Exception as exc:  # bad JSON, missing key, model violation — all fatal
        raise SeedError(f"{path.name}: {exc}") from exc
    if not corpus_lines(corpus):
        raise SeedError(f"{path.name}: corpus {corpus!r} is empty")
    return Seed(rule=rule, corpus=corpus)


def discover_seeds() -> dict[str, Seed]:
    """Every seeds/*.json keyed by fingerprint_id; duplicates are fatal."""
    if not SEEDS_DIR.is_dir():
        raise SeedError(f"seeds directory not found: {SEEDS_DIR}")
    files = sorted(SEEDS_DIR.glob("*.json"))
    if not files:
        raise SeedError(f"no seed files in {SEEDS_DIR}")
    seeds: dict[str, Seed] = {}
    for path in files:
        seed = load_seed(path)
        if seed.rule.fingerprint_id in seeds:
            raise SeedError(
                f"{path.name}: duplicate fingerprint_id {seed.rule.fingerprint_id!r}"
            )
        seeds[seed.rule.fingerprint_id] = seed
    return seeds


def samples_for(seed: Seed) -> list[str]:
    """The seed's OWN lines: corpus lines whose fingerprint_id equals the
    seed's (R8 — a shared corpus, like the three-vendor CEF file, contributes
    only the lines the fingerprint function itself assigns to this seed)."""
    return [
        line for line in corpus_lines(seed.corpus)
        if fingerprint_id(line) == seed.rule.fingerprint_id
    ]


def validate_seeds(seeds: dict[str, Seed]) -> dict[str, list[str]]:
    """Activation check per seed against its own corpus lines; only failures
    come back, keyed by fingerprint_id (empty dict = all seeds may load)."""
    problems: dict[str, list[str]] = {}
    for fp_id, seed in sorted(seeds.items()):
        samples = samples_for(seed)
        if not samples:
            problems[fp_id] = [(
                f"no lines in {seed.corpus} fingerprint as {fp_id!r} "
                "(id drifted from fingerprint_id()'s output — R8)"
            )]
            continue
        errors = validate_rule_output(seed.rule, samples)
        if errors:
            problems[fp_id] = errors
    return problems


def insert_seeds(conn, seeds: dict[str, Seed]) -> int:
    """Insert every seed idempotently in ONE transaction; returns rows added."""
    from psycopg.types.json import Json  # deferred: keeps psycopg off the test path

    inserted = 0
    with conn.cursor() as cur:
        for fp_id, seed in sorted(seeds.items()):
            rule = seed.rule
            cur.execute(_INSERT_SQL, (
                rule.fingerprint_id,
                rule.version,
                rule.pattern,
                Json([m.model_dump() for m in rule.mappings]),
            ))
            inserted += cur.rowcount
    conn.commit()
    return inserted


def seed_database(conn) -> int:
    """Load, validate, insert. Returns the process exit code: 0 seeded (or all
    already present), 1 a seed is broken — nothing inserted, failure named."""
    try:
        seeds = discover_seeds()
    except SeedError as exc:
        log.error("seed load failed, nothing inserted: %s", exc)
        return 1

    problems = validate_seeds(seeds)
    if problems:
        for fp_id, errors in problems.items():
            log.error("seed %s failed activation validation: %s", fp_id, "; ".join(errors))
        log.error("seed run aborted: %d of %d seed(s) broken, nothing inserted",
                  len(problems), len(seeds))
        return 1

    inserted = insert_seeds(conn, seeds)
    log.info("seed complete: %d inserted, %d already present", inserted, len(seeds) - inserted)
    return 0


def main() -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    admin_url = os.environ.get("ADMIN_DATABASE_URL")
    if not admin_url:
        print("error: ADMIN_DATABASE_URL is not set", file=sys.stderr)
        return 2

    import psycopg  # deferred: validation half stays importable without psycopg

    with psycopg.connect(admin_url) as conn:
        return seed_database(conn)


if __name__ == "__main__":
    sys.exit(main())
