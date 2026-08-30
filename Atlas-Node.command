#!/bin/bash
# ============================================================================
# Atlas Mac Node — DOUBLE-CLICK to start. No typing required.
#
# Double-clicking this file in Finder runs it in Terminal.app: it sets up the
# Python environment the first time (one-time, ~30s), starts the blind-relay
# node, and opens the live dashboard in your browser. To stop it, just close the
# Terminal window (or press Ctrl-C).
#
# If macOS says it "cannot be opened because it is from an unidentified
# developer": right-click the file -> Open -> Open. (Only needed once.)
# ============================================================================
set -e
cd "$(dirname "$0")/backend"

echo "== Atlas Mac Node =="
if ! command -v python3 >/dev/null 2>&1; then
  echo
  echo "  Python 3 is not installed. Run  xcode-select --install  once, or"
  echo "  install from https://www.python.org/downloads/ , then double-click again."
  echo
  read -n 1 -s -r -p "Press any key to close."
  exit 1
fi

# One-time environment setup (skipped on later launches).
if [ ! -d .venv ]; then
  echo "First-time setup (about 30 seconds)…"
  python3 -m venv .venv
  ./.venv/bin/pip install --quiet --upgrade pip
  ./.venv/bin/pip install --quiet -r requirements-server.txt
  echo "Setup done."
fi

PORT=8787
# Open the dashboard once the server is up.
( sleep 2; open "http://localhost:${PORT}/" >/dev/null 2>&1 || true ) &

echo
echo "  Dashboard opening at http://localhost:${PORT}/"
echo "  On the phones, point the app at this Mac's Wi-Fi address."
echo "  Close this window (or press Ctrl-C) to stop the node."
echo
exec ./.venv/bin/python -m atlas.net.node_server --host 0.0.0.0 --port "${PORT}"
