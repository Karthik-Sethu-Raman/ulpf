# services/onboarding/Dockerfile — M2 cold-path candidate generation:
# sample split -> SLM/JSON candidate -> validation gate -> pending_review.
# Build context is the repo root (compose build.context: ..; see /.dockerignore).
FROM python:3.12-slim

WORKDIR /app

# BOTH libs first (the validation gate imports ocsf_schema.validator via
# ulpf_core), then deps (layer caching), then the service package.
# /app contains onboarding/ and libs/ so `python -m onboarding.app` imports cleanly.
COPY libs/ulpf-core/pyproject.toml /app/libs/ulpf-core/pyproject.toml
COPY libs/ulpf-core/ulpf_core/ /app/libs/ulpf-core/ulpf_core/
COPY libs/ocsf-schema/pyproject.toml /app/libs/ocsf-schema/pyproject.toml
COPY libs/ocsf-schema/ocsf_schema/ /app/libs/ocsf-schema/ocsf_schema/
COPY services/onboarding/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && pip install --no-cache-dir -e /app/libs/ulpf-core -e /app/libs/ocsf-schema

COPY services/onboarding/__init__.py /app/onboarding/__init__.py
COPY services/onboarding/config.py /app/onboarding/config.py
COPY services/onboarding/samples.py /app/onboarding/samples.py
COPY services/onboarding/generate.py /app/onboarding/generate.py
COPY services/onboarding/store.py /app/onboarding/store.py
COPY services/onboarding/app.py /app/onboarding/app.py

CMD ["python", "-m", "onboarding.app"]
