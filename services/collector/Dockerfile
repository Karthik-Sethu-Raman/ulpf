# services/collector/Dockerfile — syslog UDP/TCP + HTTP ingest producing raw.logs.
# Build context is the repo root (compose build.context: ..; see /.dockerignore).
FROM python:3.12-slim

WORKDIR /app

# ulpf-core first, then deps (layer caching), then the service package.
# /app contains collector/ and libs/ so `python -m collector.app` imports cleanly.
COPY libs/ulpf-core/pyproject.toml /app/libs/ulpf-core/pyproject.toml
COPY libs/ulpf-core/ulpf_core/ /app/libs/ulpf-core/ulpf_core/
COPY services/collector/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && pip install --no-cache-dir /app/libs/ulpf-core

COPY services/collector/__init__.py /app/collector/__init__.py
COPY services/collector/app.py /app/collector/app.py
COPY services/collector/producer.py /app/collector/producer.py

CMD ["python", "-m", "collector.app"]
