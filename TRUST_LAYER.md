# Trust Layer — design notes

The "trust layer" is the set of primitives the rest of Atlas is built on: presence-gated keys,
the identity tree and per-context pseudonyms, recovery (threshold + Secure Enclave + live-person),
append-only ledgers, and the group-space vault. This document is the architectural overview; each
mechanism is implemented in `backend/atlas/` (Python reference) and mirrored in
`ios/AtlasCore/Sources/AtlasCore/` (Swift), with cross-implementation parity vectors in
`backend/parity/parity_vectors.json`. See [`CAPABILITIES.md`](CAPABILITIES.md) for the maturity of
each capability and [`SECURITY_PRIVACY_REVIEW.md`](SECURITY_PRIVACY_REVIEW.md) for the whole-system
security/privacy review.

## Principles

- **Python is the reference-of-record.** Every primitive/protocol/property is defined and tested in
  `backend/` first, with known-answer parity vectors; Swift (and later ports) mirror the vectors
  byte-for-byte. Never change Python to match a port.
- **Value = QRNG (or hardware RNG) for long-lived keys; PoLE for session keys.** Only raw biometrics
  and wall-clock time are excluded from keys. Liveness *times and gates*; it does not supply key
  material for long-lived keys.
- **Liveness is not identity.** No stored physiological template; no biometric identification. The
  *who* is bound by the device's own Secure Enclave biometric (Face ID / Touch ID), which Atlas
  never sees. Physiology raises spoof cost via multi-axial coherence; it is not proof of
  unspoofability.
- **Decentralized biometrics, not biometric-free.** Atlas *does* use biometrics (Enclave at
  enrollment; physiological signals for liveness). The differentiator is that they are never in a
  central store — not that they are avoided.

## Architecture, in one paragraph

A user's **System-ID** (the digital you) is a stable post-quantum root (SPHINCS+ → System-ID →
children) whose signing/derivation authority is a **split Threshold Secret Key (TSK)**: a user-held
half (Atlas Card / device / recovery card) and a server-side half that is **blind, HSM-sealed,
sharded across independent jurisdictions, and proactively refreshed**. Alongside the user's half of
the TSK, the user also holds **half of the key that unlocks their biometrics**; the biometric
material is sealed as **ciphertext the user can store anywhere** (self, home node, laptop, split
among guardians, or server-sharded — their choice), because *storage is decoupled from
confidentiality*. Recovery runs in **tiers** — device-present (cryptographic) → social
(**guardianship**, a private, possibly-silent set only the user knows) → physical-self (face + ID +
**unlinkable recovery pseudonym** verified in person by an accountable verifier) — so a user is
**never permanently locked out; the last credential is you**, while the System-ID **stays secret
throughout recovery** and the system stores **nothing about you** (no biometric, no ID copy, no
identity — only blind shares). Every conversation or space can choose to be **anchored on a ledger**:
per-user/per-space append-only individual ledgers whose **commitments (not content)** are anchored to
a decentralized **global ledger** (drand/beacon + blockchain), giving **linkability where you want it
and unlinkability where you want it**.

## What the core provides

| Concern | Where |
|---|---|
| Split-TSK: user half + blind server-HSM half; TSK = SPHINCS+ root → System-ID → children | `backend/atlas/keys/identity.py` |
| Selective linkability: `epoch_pseudonym = H("atlas/epoch-pseudonym", secret, drand_round)` — per-context + per-epoch, one-way, DP; descends from the verified System-ID (hash-based ⇒ post-quantum) | `backend/atlas/realid/pseudonym.py` |
| Per-scope pseudonyms: `nym = PRF(root_secret, space_id)` + domain-separated nullifier (structural sybil-resistance) | `backend/atlas/realid/space_pseudonym.py` |
| Anonymous-credential unlinkability (Pointcheval–Sanders) behind a swappable scheme seam | `backend/atlas/realid/ps_credential.py` |
| Group session: N users co-derive one live LK through a blind relay; identity-authenticated handshake + safety numbers | core session |

## Security review (2026-07)

An independent module-by-module review found real gaps; each was reproduced with a live PoC and then
fixed, with a regression test that runs the original attack and now fails it.

| Sev | Module | Fix |
|---|---|---|
| CRIT | `space_pseudonym` | Sybil hole (any root admitted) → registration now requires a personhood Merkle-membership proof and derives nym/nullifier from the verified root. 1000 fake roots → 0. |
| HIGH | `server_ratchet` | Honest-dealer → **Feldman VSS**: shares are commitment-verifiable, a cheating shard is detected, and `C_0 = G^secret` proves the System-ID never moves. |
| HIGH | `attestation/device` | Evidence never verified → capabilities admitted only on a valid Ed25519 attestation signature; forged/absent fails closed. |
| HIGH | `agility` | Downgrade → `negotiate` gains a strength-floor predicate + channel-binding. |
| HIGH | `spaces/space` | `governance < access` silent data-loss → enforced `governance ≥ access`. |
| MED | `spaces/space` | `remove_member` wasn't real revocation → now rotates the root + re-encrypts the vault. |
| MED | `oprf` + `zk` | Missing subgroup check → `element^Q == 1` enforced on every received element. |
| MED | `global_anchor` | Backdatable → drand round must be non-decreasing; length-prefixed hashing; corrected to tamper-EVIDENT-via-anchoring. |

Backend + Swift suites green after every fix.

## Mechanisms

- **Threshold biometric-key model** (`recovery/threshold_seal.py`) — the key that unlocks a user's
  biometrics = user-TSK-bound half ∧ (m-of-n custodians). Custodians can be yourself, a home node +
  laptop, a guardianship set, or server shards. The sealed ciphertext carries **no confidentiality
  dependency on where it is stored** (storage ⟂ confidentiality).
- **Guardianship net** (`recovery/guardianship.py`) — a private guardian set (only the user knows
  the full membership), supporting **silent** custodians (passive device-node shares — anti-collusion,
  anti-coercion) and **witting** guardians (human veto). Invariant: no all-institutional subset
  reaches threshold.
- **Recovery tiers** (`recovery/tiers.py` + `realid/recovery_anchor.py`) — device-present → social →
  physical-self (name + password + a **live recovery person**, an accountable in-person verifier).
  The total-loss anchor stores **no biometric at all**; the System-ID stays secret throughout, and
  physical-self recovery reconstructs you from your unlinkable recovery pseudonym, not from anything
  stored about you.
- **Individual ledgers + global anchoring** (`ledger/`) — per-user/per-space append-only ledgers;
  only commitments / Merkle roots (never content) are anchored to a decentralized global ledger
  (drand/beacon + blockchain).
- **Per-conversation ledger choice** (`ledger/conversation.py`) — accountable-anchored (signed +
  committed, selectively provable later) vs deniable (AEAD-only, commits nothing).
- **OPRF hardening** (`recovery/oprf.py`) — the server-side half is a blind OPRF (RFC 9497): the
  client learns `F(key, input)`, the server learns nothing; the password is a **selector, never a
  key**. Additive key sharding (no shard evaluates alone) + proactive refresh.
- **Universal-trust pillars** — crypto-agility seam (`crypto/agility.py`), a platform-neutral
  device-attestation contract (`attestation/device.py` → `AssuranceTier`), group spaces
  (`spaces/space.py`: a k-of-n threshold root + presence-gated ciphertext-only vault + reshare-managed
  membership), per-scope pseudonyms (`realid/space_pseudonym.py`), and a server-share proactive
  ratchet (`keys/server_ratchet.py`) that rotates only the exposed server share while the System-ID
  is unchanged.
- **ZK proof-of-liveness** (`zk/liveness_proof.py`) — a sound non-interactive zero-knowledge proof
  that a committed liveness score `w ≥ τ`, revealing nothing else (Pedersen commitments + per-bit
  Chaum–Pedersen OR-proofs composed into a bounded range proof, non-interactive via Fiat–Shamir).
  A reference NIZK (not a SNARK); production would use a curve-based system (Bulletproofs / STARK).

> **Deployment note.** The server-side distribution (HSM + multi-jurisdiction sharding) is a
> precondition, not a feature. A single-jurisdiction deployment — including this proof of concept —
> *simulates* the topology and delivers **none** of the seizure/subpoena-resistance guarantee. Don't
> read the single-machine PoC as providing the distributed property.
