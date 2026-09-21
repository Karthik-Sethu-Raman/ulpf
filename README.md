# ULPF — Universal Log Pre-processing Framework

SIH 2026 PS 26156 MVP. Status: M2 onboarding loop complete — the milestone
exit is `python scripts/smoke.py` (all 8 checks PASS).

- `services/` — collector, pipeline, gateway, onboarding (drift in M3)
- `libs/ulpf-core` — fingerprinting, parsing, IDs, hash chain (single implementation)
- `libs/ocsf-schema` — curated OCSF subset schema + validator
- `web/` — React dashboard
- `simulator/` — multi-vendor traffic player
- `deploy/` — docker-compose, migrations
- `scripts/smoke.py` — M1+M2 acceptance gate (live E2E incl. forced replay + the onboarding hero loop)
- `legacy-demo/` — the original hackathon demo, frozen. See its README.

## Collector ingest

Syslog UDP + TCP on 5514, HTTP `POST /v1/ingest` on 8080 (≤1000 lines/request).
Oversized input is handled asymmetrically by design: UDP drops just the one
oversized datagram (each datagram is an independent event), while TCP closes
the connection — a byte stream has no line boundary to resynchronize to.

## Quickstart

```bash
cd deploy && docker compose --profile slm-4b up -d --build
```

Brings up the M1 pipeline plus the M2 onboarding loop and the default SLM
tier: `qwen3:4b` behind the `ollama-4b` sidecar (runs on 8GB boxes; the model
is pulled by the sidecar on first start — a one-time multi-GB download).
16GB boxes may upgrade: `--profile slm-8b` plus `ULPF_OLLAMA_URL=http://ollama-8b:11434`
and `ULPF_OLLAMA_MODEL=qwen3:8b` in `deploy/.env` (see `.env.example`). The
ollama sidecars publish **no host port** — they are reachable only inside the
compose network (the onboarding service is their only client).

Hero loop (unknown appliance → candidate rule): play the unknown `newapp`
corpus at the collector, then watch the Review Queue while onboarding splits
samples, asks the SLM, validates, and stores the candidate. On the default
`qwen3:4b` tier the SLM may store no rule on modest hardware — in that case
the fingerprint stays backlogged until a candidate lands (author one via the
dashboard or `POST /api/rules/manual`); see docs/m2-slm-sanity.md for the
measured tier numbers. The full lifecycle — grants, version minting, backlog
re-parse — is recorded in docs/m2-rule-lifecycle.md:

```bash
docker compose --profile sim run --rm simulator --eps 25 --duration 20 --mode new-appliance
open http://localhost:3000        # Review Queue: the newapp fingerprint lands as pending_review when a candidate stores
# sustained live traffic for the dashboard (`run` needs the sim profile re-activated):
docker compose --profile sim run --rm simulator --eps 20 --duration 300 --loop
```

Acceptance gate (starts the stack itself — bring the SLM tier profile so the
onboarding sidecar is up):

```bash
python scripts/smoke.py          # end-to-end acceptance incl. forced replay + hero loop
```

The smoke runs the simulator over the golden corpora, then verifies:
lossless ingest (raw delta == sent), the parsed/unparsed split per
fingerprint, raw traceability (API + SQL join with recomputed sha256),
forced replay idempotency (Kafka consumer-group delete + pipeline restart:
raw events unchanged, raw_batches grown), an independent recomputation of
every raw_batches merkle root plus full per-partition chain linkage (A–E),
then the M2 onboarding loop: the newapp hero loop through approve → backlog
re-parse (SLM candidate if one stores within `ULPF_SMOKE_SLM_WAIT_S`
(default 300s), a locally pre-validated hand-authored candidate otherwise),
the deterministic zenwall manual rule (G), and a replay-stability check with
active rules, samples included (H).

Smoke host deps (Python 3.13 tested): `psycopg[binary]` plus the two libs
importable — `pip install -e libs/ulpf-core -e libs/ocsf-schema` (the smoke
computes fingerprints and pre-validates hand-authored rules with the same
`ulpf_core` gate the services run). No confluent-kafka
on the host: Kafka interaction goes through `docker compose exec redpanda rpk`,
and the simulator runs in its own container (the services'
`confluent-kafka==2.5.0` pin is in-image only, py3.12). The smoke is
delta-based: the database is never reset, so re-runs accumulate and re-verify
the full accumulated chain every time.

Ports: web 3000, gateway 8000, Postgres published on host **5433** — 5432 is
deliberately left to any native Postgres on the dev box (host connections to
5432 would silently hit that one). Inside the compose network everything still
uses `postgres:5432`.

CI (`.github/workflows/ci.yml`): `ruff check .` + `pytest` (libs, services,
simulator) on Python 3.12; web `npm ci`, vitest, `npm run build` on Node 22.
The dashboard is React 19.2 + Vite 8.3 + TypeScript 6.
