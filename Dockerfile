# ATLAS PoC — clone, build, and SEE a real behaviour in one command:
#
#   docker build -t atlas-poc . && docker run --rm atlas-poc
#
# -> a sealed message opens while a live human is present, then REFUSES after a liveness break.
# That is ~10 seconds and self-evidently a real behaviour, not a claim.
FROM python:3.11-slim

WORKDIR /atlas
COPY backend/ ./backend/
COPY README.md ./
# Installs the pure-Python default deps from backend/pyproject.toml (Ursa BBS+ stays optional; a
# publicly-reachable node additionally installs liboqs-python — see deploy/install-node.sh).
RUN pip install --no-cache-dir -e ./backend

WORKDIR /atlas/backend
# Default: the 10-second headline demo. Override the command to run others:
#   docker run --rm atlas-poc python -m pytest -q          # the full test suite
#   docker run --rm atlas-poc atlas-demo-records           # sealed medical/records lifecycle
#   docker run --rm -p 8787:8787 atlas-poc python -m atlas.net.node_server   # a blind relay node
CMD ["atlas-demo-liveness"]
