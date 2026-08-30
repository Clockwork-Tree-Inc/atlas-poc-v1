# Atlas PoC — Backend / Protocol Core (Milestone 1)

This is the Mac-side server/verifier node and the kit-independent protocol core
from the *Atlas PoC Build Spec (FINAL)*. It is the full substance of
**Milestone 1** (security + cryptographic identity, no liveness) plus the
simulation-tier liveness math (§11 "Partial (sim)").

Everything here **runs and is fully tested off-device**. The iOS / Secure-Enclave
/ BLE / camera / JavaCard surfaces are written separately as Swift source and
verified on the Mac + physical kit — they cannot be exercised in this
environment.

## What's implemented (with spec citations)

| Area | Module | Spec |
|------|--------|------|
| AES-256-GCM, HKDF<SHA-256>, SHA-3 hashes | `atlas/crypto/primitives.py` | §1.3, §4.1 |
| Hybrid KEM — X-Wing-style **ML-KEM-768 + X25519** | `atlas/crypto/kem.py` | §1.3, ATLAS VIII §B.2 |
| Hybrid signatures **ML-DSA-65 + Ed25519**; **SPHINCS+** root | `atlas/crypto/sign.py` | §1.3 |
| Shamir **2-of-3** over GF(256) | `atlas/crypto/shamir.py` | §1.3, §7.3 |
| Public beacon — drand client + offline drand-shaped stand-in | `atlas/beacon/drand.py`, `local_beacon.py` | §3.2 |
| Private beacon — presence-fired Server-QRNG (Living Key) | `atlas/beacon/qrng.py` | §3.1, §3.2 |
| Session key (coupled + decoupled) + forward-secret ratchet | `atlas/keys/derivation.py` | §2.2 |
| Context separators + scoped capability tokens | `atlas/keys/derivation.py`, `tokens.py` | §2.3 |
| Identity tree TSK→System-ID→children, 1:1 verification | `atlas/keys/identity.py` | §2.1, §7.1 |
| Threshold recovery — stratified: Enclave (device-present) vs portable shares (total-loss) | `atlas/keys/recovery.py`, `enclave.py` | §7.2, §7.3 |
| Bayesian liveness gate + PoLE state (no `ring_SE_sig` at Tier 3) | `atlas/liveness/bayes.py` | §5.2 |
| Synthetic live/spoof presence streams | `atlas/liveness/synthetic.py` | §5.1, §11 |
| Ratchet-paced signed attestation + removal states | `atlas/liveness/attestation.py` | §5.3, §5.4 |
| Device node (composes session key locally) | `atlas/session/device.py` | §2, §3 |
| Recognition + evolving tunnel — **hybrid ML-KEM-768 + X25519** (post-quantum) | `atlas/session/recognition.py` | §4 |
| Vault encrypted at rest + PQC key-wrap | `atlas/session/vault.py` | §4.1 |
| Two send modes (normal / verified-human-only) | `atlas/session/tunnel.py` | §9 |
| Content provenance: **accountable attribution** (resolvable under cause) + ledger anchor; PAD advisory | `atlas/provenance/` | §8, §10.2 |
| Payment arm-per-use (protocol logic; **not air-gapped in sim**) | `atlas/payment/` | Payment spec §4 |

## Frozen §3.2 / §22.1 decisions (PoC defaults)

Set once in `atlas/params.py`:

1. **Inter-arrival timing is committed** into the next QRNG firing (not merely
   observed) — otherwise forward secrecy is decorative.
2. **Tunnel is symmetric** (jointly rooted): recognition is a key-agreement with
   canonical ordering; neither device leads.
3. **Server returns timed randomness only**; each device composes its session
   key locally (structural — the server never holds a finished session key).
4. Recognition window **ε = 2.0 s**.
5. Epoch length floor/cap = **3 s / 30 s** (the replay window).

## Run it

```bash
cd backend
pip install -r requirements.txt          # pure-Python / prebuilt wheels; no GitHub, no C toolchain
python -m pytest -q                      # 59 tests
python -m demos.demo_milestone1_text     # Milestone-1 exit test, end to end
python -m demos.demo_milestone5_photo    # Milestone-5 capstone (provenanced photo)
```

### Milestone-1 exit test (§13, §10.1)

`demos/demo_milestone1_text.py` runs both wallets in one process and shows:

* **Mode 1** encrypted text A→B over the recognition-seeded tunnel;
* **forward secrecy** — a 2nd message on a ratcheted key that a captured earlier
  key cannot read;
* **Mode 2** verified-human-only viewing — the live, on-network recipient opens
  it while offline / bot / expired-epoch / stolen-device holders are all denied.

## Notes on this environment

* **drand (`api.drand.sh`) is blocked** by egress policy here, so the public
  beacon uses a deterministic, drand-shaped offline stand-in (`LocalBeacon`).
  Swap in `DrandHTTPBeacon` on the Mac for the real League-of-Entropy chain; both
  satisfy the same `Beacon` interface. The HTTP client is unit-tested against a
  stub transport.
* **PQC**: `liboqs` cannot build here (its source pull from GitHub is blocked),
  so the core uses pure-Python ML-KEM-768 / ML-DSA-65 and a prebuilt SPHINCS+
  wheel. On the Mac, `liboqs`/`python-oqs` (and CryptoKit on iOS) are drop-in
  behind the same module interfaces. Verify CryptoKit's PQC surface against your
  target iOS SDK before relying on it.
* Everything is **hybrid (classical + PQC)** per §1.3.
