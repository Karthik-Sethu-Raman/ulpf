# deploy/migrate.Dockerfile — one-shot schema migration runner (compose service `migrate`).
# Build context is the repo root (compose build.context: ..).
FROM python:3.12-slim

RUN pip install --no-cache-dir "psycopg[binary]==3.2.1"

WORKDIR /app
COPY deploy/migrate.py /app/deploy/migrate.py
COPY deploy/migrations/ /app/deploy/migrations/

ENTRYPOINT ["python", "/app/deploy/migrate.py", "--dir", "/app/deploy/migrations"]
