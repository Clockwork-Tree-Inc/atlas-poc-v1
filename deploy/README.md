# Atlas node deployment (VPS bring-up runbook)

Target fleet: **1× Infomaniak VPS Cloud (~12 GB)** = main node (register + SearXNG now, OLMo-7B
later) + **2× VPS Lite** = blind relays. Debian/Ubuntu assumed. Same kit works on a Mac/laptop node.

## Security posture (read first)

* **Relays are KEYLESS** — they store-and-forward sealed blobs (rotating mailbox ids, no directory).
  Host compromise = DoS, never data. Nothing else goes on them.
* **The main node's AI sees prompts in RAM while inferring** — beta claim is "we don't look"
  (it's your own rented box). "Can't see" arrives with confidential-compute VMs.
* **NO key custody on any VPS.** The optional TSK "server" shard may be parked here later —
  it is mathematically useless alone (2-of-n + anti-all-institutional invariant) — but the
  HSM-grade custody story is explicitly NOT a plain VPS.
* **PUBLIC EXPOSURE IS GATED**: the bundled reference ML-KEM is NOT constant-time; a publicly
  reachable node must first wire a constant-time KEM (liboqs) — the code fails closed on this
  (`require_constant_time_kem`). Until then, run the mesh PRIVATELY (Option A below).

## Option A (recommended for the beta): private mesh via Tailscale/WireGuard

No public ports, no TLS certs, no constant-time-KEM blocker — the boxes and your phone join one
private network; the app reaches the node at its mesh IP.

```sh
# on each box (and install the Tailscale app on the iPhone/Mac):
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

Then install the node (below) and point the app at `http://<tailscale-ip>:8787`.

## Option B: public exposure (LATER — after the liboqs swap)

Reverse-proxy with Caddy for TLS; only after the constant-time KEM lands. Not for now.

## Install the node (main box and relays — same software, different roles)

```sh
sudo bash deploy/install-node.sh          # from a clone of the PRIVATE repo
```

What it does: installs python3.11+ + venv, creates the `atlas` system user, installs
`deploy/atlas-node.service` (systemd), starts the node on port 8787. Logs:
`journalctl -u atlas-node -f`. Storage under `/var/lib/atlas`.

## SearXNG (main box only) — the AI's live wider-web search

```sh
sudo apt-get install -y docker.io docker-compose-plugin
sudo docker compose -f deploy/searxng-compose.yml up -d      # serves on :8888
```

The app's WebLibrary gains a node-backed source pointed at `http://<main-node>:8888/search?format=json&q=...`.

## Roles

| box            | runs                          | holds keys? |
|----------------|-------------------------------|-------------|
| VPS Cloud 12GB | node server + SearXNG (+7B later) | no (optional inert TSK shard later) |
| VPS Lite ×2    | node server (relay role)      | no          |

## Bring-up checklist

1. `tailscale up` on all boxes + phone.
2. `install-node.sh` on all three; verify `curl http://127.0.0.1:8787/` locally.
3. SearXNG compose on the main box.
4. Point the app: Developer tab → node URL → `http://<main-tailscale-ip>:8787`.
5. Two-device test: message through the relay; verify the relay disk holds only sealed blobs.
6. LATER (public): liboqs constant-time KEM → Caddy TLS → open 443.
