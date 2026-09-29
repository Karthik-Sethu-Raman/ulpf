# services/drift/Dockerfile — M3 drift detection: stateless window recompute,
# tier-1 invariants, INSERT-only drift_windows writes. Postgres only, no Kafka.
# Build context is the repo root (compose build.context: ..; see /.dockerignore).
FROM python:3.12-slim

WORKDIR /app

# BOTH libs first (pipeline-image pattern), then deps (layer caching), then
# the service package. /app contains drift/ and libs/ so `python -m drift.app`
# imports cleanly. psycopg is the only direct dep — windows/tier-1 are stdlib
# plus ulpf_core (regex/pydantic arrive via ulpf-core's own pins).
COPY libs/ulpf-core/pyproject.toml /app/libs/ulpf-core/pyproject.toml
COPY libs/ulpf-core/ulpf_core/ /app/libs/ulpf-core/ulpf_core/
COPY libs/ocsf-schema/pyproject.toml /app/libs/ocsf-schema/pyproject.toml
COPY libs/ocsf-schema/ocsf_schema/ /app/libs/ocsf-schema/ocsf_schema/
COPY services/drift/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && pip install --no-cache-dir -e /app/libs/ulpf-core -e /app/libs/ocsf-schema

COPY services/drift/__init__.py /app/drift/__init__.py
COPY services/drift/config.py /app/drift/config.py
COPY services/drift/windows.py /app/drift/windows.py
COPY services/drift/detect.py /app/drift/detect.py
COPY services/drift/enforce.py /app/drift/enforce.py
COPY services/drift/store.py /app/drift/store.py
COPY services/drift/app.py /app/drift/app.py

CMD ["python", "-m", "drift.app"]
