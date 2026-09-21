# services/gateway/Dockerfile — FastAPI gateway: stats, current-view events,
# raw trace, SSE, chain head (read-only DB access as gateway_role), plus the
# M2 rule-lifecycle write path (writes.py, rules_role over WRITE_DATABASE_URL).
# Build context is the repo root (compose build.context: ..; see /.dockerignore).
FROM python:3.12-slim

WORKDIR /app

# BOTH libs first: writes.py revalidates candidates via ulpf_core.validation
# (Task 3 gate), whose parse() FAILS CLOSED without ocsf_schema's validator —
# the write path must not ship without it. Then deps (layer caching), then the
# service package. /app contains gateway/ and libs/ so `python -m gateway.app`
# imports cleanly.
COPY libs/ulpf-core/pyproject.toml /app/libs/ulpf-core/pyproject.toml
COPY libs/ulpf-core/ulpf_core/ /app/libs/ulpf-core/ulpf_core/
COPY libs/ocsf-schema/pyproject.toml /app/libs/ocsf-schema/pyproject.toml
COPY libs/ocsf-schema/ocsf_schema/ /app/libs/ocsf-schema/ocsf_schema/
COPY services/gateway/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && pip install --no-cache-dir -e /app/libs/ulpf-core -e /app/libs/ocsf-schema

COPY services/gateway/__init__.py /app/gateway/__init__.py
COPY services/gateway/app.py /app/gateway/app.py
COPY services/gateway/queries.py /app/gateway/queries.py
COPY services/gateway/writes.py /app/gateway/writes.py

CMD ["python", "-m", "gateway.app"]
