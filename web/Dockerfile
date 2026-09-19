# web/Dockerfile — build the Overview SPA, then serve it (plus /api/* via the
# bundled Caddyfile) with caddy:2-alpine. Compose builds this with
# context: .. (repo root), so every COPY path is prefixed web/.
# Air-gap: build inputs are local; the served app makes no external requests.
FROM node:22 AS build
WORKDIR /app

# Lockfile first for layer caching; ci is exact, i is the fallback.
COPY web/package.json web/package-lock.json ./
RUN npm ci || npm i

# Sources (root .dockerignore keeps host node_modules out of the context).
COPY web/ ./
RUN npm run build

FROM caddy:2-alpine
COPY web/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /app/dist /srv
EXPOSE 3000
