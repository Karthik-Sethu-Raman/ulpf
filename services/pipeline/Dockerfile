# services/pipeline/Dockerfile — sole raw.logs consumer: idempotent raw-first
# batches with per-partition hash chain, parse, normalized emit.
# Build context is the repo root (compose build.context: ..; see /.dockerignore).
FROM python:3.12-slim

WORKDIR /app

# BOTH libs first (controller R15: the canary imports ocsf_schema.validator),
# then deps (layer caching), then the service package.
# /app contains pipeline/ and libs/ so `python -m pipeline.worker` imports cleanly.
COPY libs/ulpf-core/pyproject.toml /app/libs/ulpf-core/pyproject.toml
COPY libs/ulpf-core/ulpf_core/ /app/libs/ulpf-core/ulpf_core/
COPY libs/ocsf-schema/pyproject.toml /app/libs/ocsf-schema/pyproject.toml
COPY libs/ocsf-schema/ocsf_schema/ /app/libs/ocsf-schema/ocsf_schema/
COPY services/pipeline/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && pip install --no-cache-dir -e /app/libs/ulpf-core -e /app/libs/ocsf-schema

COPY services/pipeline/__init__.py /app/pipeline/__init__.py
COPY services/pipeline/db.py /app/pipeline/db.py
COPY services/pipeline/hashchain.py /app/pipeline/hashchain.py
COPY services/pipeline/rules.py /app/pipeline/rules.py
COPY services/pipeline/worker.py /app/pipeline/worker.py

CMD ["python", "-m", "pipeline.worker"]
