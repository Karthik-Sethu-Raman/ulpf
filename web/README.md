# web/ — ULPF Overview dashboard (M1)

React + Vite SPA consuming the frozen M1 gateway API (`services/gateway`)
same-origin under `/api`: live SSE feed, stats cards, raw-traceability drawer.
Air-gapped: system fonts, no CDN, no external requests.

## Run

```sh
npm i
npm run dev        # Vite dev server; /api proxied to http://localhost:8000
```

## Verify

```sh
npm run test       # vitest (useEventStream hook tests)
npm run build      # tsc -b && vite build
```

## Deploy

`deploy/docker-compose.yml` builds `web/Dockerfile` (node:22 build stage →
caddy:2-alpine serving `dist/` + `Caddyfile`, which reverse-proxies `/api/*`
to `gateway:8000`) on port 3000.
