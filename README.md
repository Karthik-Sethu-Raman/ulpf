# ULPF — Universal Log Pre-processing Framework

SIH 2026 PS 26156 MVP. Status: M1 walking skeleton in development.

- `services/` — collector, pipeline, gateway (+ onboarding, drift in M2/M3)
- `libs/ulpf-core` — fingerprinting, parsing, IDs, hash chain (single implementation)
- `libs/ocsf-schema` — curated OCSF subset schema + validator
- `web/` — React dashboard
- `simulator/` — multi-vendor traffic player
- `deploy/` — docker-compose, migrations
- `legacy-demo/` — the original hackathon demo, frozen. See its README.
