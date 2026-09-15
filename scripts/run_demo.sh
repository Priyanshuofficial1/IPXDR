#!/usr/bin/env bash
set -euo pipefail
python -m uvicorn backend.api.main:app --host 127.0.0.1 --port "${IPXDR_PORT:-8000}" &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT
sleep 1
python scripts/demo.py
wait "$pid"
