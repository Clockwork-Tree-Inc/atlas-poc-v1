#!/usr/bin/env bash
# Atlas node installer (Debian/Ubuntu). Run from a clone of the repo: sudo bash deploy/install-node.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
echo "== Atlas node install from $REPO_DIR =="

apt-get update -y
# python + a C/CMake toolchain: liboqs (constant-time ML-KEM) builds from source below.
apt-get install -y python3 python3-venv python3-pip cmake ninja-build gcc libssl-dev git

id -u atlas >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/atlas atlas

install -d -o atlas -g atlas /var/lib/atlas /opt/atlas
cp -R "$REPO_DIR/backend" /opt/atlas/backend
chown -R atlas:atlas /opt/atlas

sudo -u atlas python3 -m venv /opt/atlas/venv
sudo -u atlas /opt/atlas/venv/bin/pip install -q --upgrade pip
sudo -u atlas /opt/atlas/venv/bin/pip install -q -r /opt/atlas/backend/requirements-server.txt

# CONSTANT-TIME ML-KEM (security review #7). A publicly-reachable node decapsulates, so the
# pure-Python kyber-py reference (timing-leaky) is not acceptable here. liboqs-python builds the
# audited constant-time C liboqs on first import; do that build now, as the atlas user, and then
# assert the guard is satisfied so the install FAILS LOUDLY if the constant-time backend is missing
# — a public node must never fall back to the reference impl.
sudo -u atlas /opt/atlas/venv/bin/pip install -q liboqs-python
sudo -u atlas /opt/atlas/venv/bin/python -c "import oqs"   # triggers the one-time liboqs C build
sudo -u atlas env PYTHONPATH=/opt/atlas/backend /opt/atlas/venv/bin/python -c \
  "from atlas.crypto.kem import require_constant_time_kem, KEM_BACKEND; require_constant_time_kem(); print('KEM backend:', KEM_BACKEND)" \
  || { echo 'FATAL: constant-time ML-KEM backend not available — refusing to install a public node with a timing-leaky KEM.'; exit 1; }

install -m 644 "$REPO_DIR/deploy/atlas-node.service" /etc/systemd/system/atlas-node.service
systemctl daemon-reload
systemctl enable --now atlas-node

sleep 2
systemctl --no-pager --lines=5 status atlas-node || true
echo "== done: node on :8787 (journalctl -u atlas-node -f) =="
