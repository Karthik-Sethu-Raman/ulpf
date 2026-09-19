# deploy/seed.Dockerfile — one-shot seed-rule loader (compose service `seed`).
# pipeline_role is SELECT-only on rules by design, so seeding connects as the
# admin via ADMIN_DATABASE_URL and runs after migrations (controller R18).
# Build context is the repo root (compose build.context: ..; see /.dockerignore).
FROM python:3.12-slim

WORKDIR /app

# BOTH libs: validation needs ulpf_core.parsing, and its activation check
# FAILS CLOSED when ocsf_schema is unimportable — so the seed image installs
# exactly what the worker image installs. Deps (layer caching) next.
COPY libs/ulpf-core/pyproject.toml /app/libs/ulpf-core/pyproject.toml
COPY libs/ulpf-core/ulpf_core/ /app/libs/ulpf-core/ulpf_core/
COPY libs/ocsf-schema/pyproject.toml /app/libs/ocsf-schema/pyproject.toml
COPY libs/ocsf-schema/ocsf_schema/ /app/libs/ocsf-schema/ocsf_schema/
COPY services/pipeline/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && pip install --no-cache-dir -e /app/libs/ulpf-core -e /app/libs/ocsf-schema

COPY services/pipeline/__init__.py /app/pipeline/__init__.py
COPY services/pipeline/seed_rules.py /app/pipeline/seed_rules.py
COPY services/pipeline/seeds/ /app/pipeline/seeds/

# The golden corpora the seeds validate against at load time (fail closed:
# an unreadable corpus is an error, never a silent load).
COPY libs/ulpf-core/tests/data/golden/ /app/golden/
ENV ULPF_GOLDEN_DIR=/app/golden

CMD ["python", "-m", "pipeline.seed_rules"]
