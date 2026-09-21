#!/bin/sh
# deploy/ollama-entrypoint.sh — serve, pull $MODEL until local, wait on serve.
# PID1 is this shell: `wait` keeps the backgrounded `ollama serve` as the
# long-running job after the pull finishes. Exec bit set both ways for NTFS:
#   chmod +x deploy/ollama-entrypoint.sh
#   git update-index --chmod=+x deploy/ollama-entrypoint.sh
set -e
ollama serve &
sleep 2
ollama pull "$MODEL"
wait
