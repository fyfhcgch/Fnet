#!/bin/sh
# Start the Fnet WebUI.  Extra arguments are appended to the usual command,
# e.g. `docker run ... fnet:latest --port 9000`.
set -eu

HOST="${FNET_HOST:-0.0.0.0}"
PORT="${FNET_PORT:-8765}"

if [ "$#" -gt 0 ]; then
    exec python -m fnet "$@"
fi

exec python -m fnet --host "$HOST" --port "$PORT" --no-browser
