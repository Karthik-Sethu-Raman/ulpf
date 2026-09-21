# PPT accuracy fixes (spec §17 — mandated before finals; do them before this submission)

The deck (`references/sih-ps-26156-ppt-print.pdf`) predates the M2 merge. Three
lines no longer match what shipped — suggested replacements:

1. **Slide 3, Onboarding engine bullet** — "Local SLM (Ollama + Granite 4.1)"
   → **"Local SLM (Ollama, tiered Qwen3 4B/8B — CPU-only, offline)"**
   Shipped default tier is qwen3:4b (`deploy/docker-compose.yml`,
   `docs/m2-slm-sanity.md`); Granite was a harness alternate, never the default.

2. **Slide 4, Resource-light bullet** — "billions-of-events/day throughput needs
   no GPU or inference" → **"hot-path throughput needs no GPU or inference;
   scale-out is Kafka partitions + consumer-group workers (benchmarks in M4)"**
   The spec withdrew unmeasured throughput claims (§13 benchmark honesty:
   measured numbers only — nothing extrapolated).

3. **Slide 3, Ingestion bullet** — "buffered via Kafka" → **"buffered via
   Redpanda (Kafka-protocol compatible)"** — exact and preempts the judge
   question. (The architecture diagram already words it this way.)

Also worth a glance (not a mismatch, just a risk): slides 2/4 cite Matryoshka
as "UC Berkeley/Google published research" — spec §17 flags this attribution
for re-verification; slide 6 links the julien-piet/matryoshka repo. Confirm
the affiliation wording before submission.
