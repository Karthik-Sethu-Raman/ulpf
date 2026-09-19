# services/gateway/Dockerfile — FastAPI gateway: stats, current-view events,
# raw trace, SSE, chain head. Read-only DB access as gateway_role (SELECT only).
# Build context is the repo root (compose build.context: ..; see /.dockerignore).
FROM python:3.12-slim

WORKDIR /app

# No ulpf-core/ocsf-schema dependency: the gateway speaks plain SQL via psycopg.
COPY services/gateway/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# /app contains gateway/ so `python -m gateway.app` imports cleanly.
COPY services/gateway/__init__.py /app/gateway/__init__.py
COPY services/gateway/app.py /app/gateway/app.py
COPY services/gateway/queries.py /app/gateway/queries.py

CMD ["python", "-m", "gateway.app"]
