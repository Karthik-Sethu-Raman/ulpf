# simulator/Dockerfile — multi-vendor traffic simulator over the golden corpora.
# Build context is the repo root (compose build.context: ..; see /.dockerignore).
FROM python:3.12-slim

WORKDIR /app/simulator

# Runtime deps only: stdlib (asyncio, socket, argparse) plus httpx.
COPY simulator/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY simulator/simulate.py /app/simulator/simulate.py
COPY simulator/data/ /app/simulator/data/

# `docker compose run --rm simulator --eps 25 --duration 20` passes the flags
# straight through as argv (ENTRYPOINT, not CMD).
ENTRYPOINT ["python", "simulate.py"]
