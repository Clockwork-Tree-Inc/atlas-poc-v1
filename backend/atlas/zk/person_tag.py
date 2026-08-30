"""Person-tag with a ZERO-KNOWLEDGE binding to the hidden root — the on-the-wire gate for
person-scoped blocking + one-person-one-account, WITHOUT the host ever seeing the root.

Replaces the cleartext `realid/space_pseudonym.SpaceRegistry(root_secret, …)` path, which handed
the space host the *raw* master root (letting it derive your pseudonyms in every other space and
forge you — a cross-space-unlinkability break flagged by review). Here the host sees only
(C, N, proof):

  root commitment  C = G^x · Hh^s                       (the enrolled/credential commitment to root x)
  scope generator  B = HashToGroup("…scope" ‖ scope)
  nullifier        N = B^x                              (VRF-style: one per (person, scope),
                                                         cross-scope-unlinkable under DDH, one-way)
  binding (DLEQ)   prove ∃ x,s : C = G^x·Hh^s  ∧  N = B^x    (the SAME x binds C and N)

…revealing neither x nor the blinding s. Same-person+same-scope ⇒ identical N (one-per-person,
blockable); different scope ⇒ unrelated N (unlinkable). The Fiat–Shamir challenge binds C, N, the
generators, the scope, the epoch, and a verifier nonce, so a proof can't be replayed or mixed.

Finite-field (MODP) Python reference, consistent with `zk/liveness_proof.py` / `recovery/oprf.py`;
production uses a curve/STARK. This adopts the algebraic VRF nullifier (both crypto reviews
converged on it) — it AMENDS Math Spec §A/§17, whose HKDF(TSK,scope) form can't be proven in ZK
without a Keccak circuit the repo doesn't have.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..crypto.primitives import H
from ..recovery.oprf import _P as P
from ..recovery.oprf import _Q as Q
from ..recovery.oprf import _i2osp, _in_subgroup, _random_scalar, hash_to_group
from .liveness_proof import G, Hh, _fs_scalar, pedersen


def root_scalar(root_secret: bytes) -> int:
    """Map a root secret to a nonzero scalar in [1, Q)."""
    x = int.from_bytes(H(b"atlas/zk/person-root", root_secret), "big") % Q
    return x or 1


def scope_generator(scope: bytes) -> int:
    """A nothing-up-my-sleeve subgroup generator unique to this scope (unknown dlog to G)."""
    return hash_to_group(b"atlas/zk/person-tag/scope" + scope)


def commit_root(x: int) -> tuple[int, int]:
    """The credential's Pedersen commitment to root scalar x, with fresh blinding s. Returns (C, s).
    In the full system C comes from the re-randomized verified-human credential, not a fresh commit."""
    s = _random_scalar()
    return pedersen(x, s), s


def nullifier(x: int, scope: bytes) -> int:
    """N = B^x — deterministic per (root, scope): one-per-person-per-scope, cross-scope unlinkable."""
    return pow(scope_generator(scope), x % Q, P)


@dataclass(frozen=True)
class PersonTagProof:
    scope: bytes
    epoch: int
    nonce: bytes
    C: int          # commitment to the root (what the credential certifies)
    N: int          # the scope nullifier — the person-tag the host keys blocking/uniqueness on
    T_C: int
    T_N: int
    z_x: int
    z_s: int


def _challenge(C: int, N: int, B: int, T_C: int, T_N: int, scope: bytes, epoch: int, nonce: bytes) -> int:
    # total-binding Fiat–Shamir: all public values + generators + scope + epoch + verifier nonce
    return _fs_scalar(_i2osp(C), _i2osp(N), _i2osp(B), _i2osp(T_C), _i2osp(T_N),
                      _i2osp(G), _i2osp(Hh), scope, _i2osp(epoch), nonce)


def prove_person_tag(x: int, s: int, C: int, scope: bytes, *, epoch: int, nonce: bytes) -> PersonTagProof:
    """Prove the scope nullifier N uses the SAME root x committed in C — a two-base Chaum–Pedersen
    DLEQ (base G with blinding Hh for C, base B for N). Reveals N only."""
    B = scope_generator(scope)
    N = pow(B, x % Q, P)
    k_x, k_s = _random_scalar(), _random_scalar()
    T_C = (pow(G, k_x, P) * pow(Hh, k_s, P)) % P
    T_N = pow(B, k_x, P)
    e = _challenge(C, N, B, T_C, T_N, scope, epoch, nonce)
    z_x = (k_x + e * (x % Q)) % Q
    z_s = (k_s + e * (s % Q)) % Q
    return PersonTagProof(scope=scope, epoch=epoch, nonce=nonce, C=C, N=N, T_C=T_C, T_N=T_N, z_x=z_x, z_s=z_s)


def verify_person_tag(pf: PersonTagProof, *, expected_epoch: int, expected_nonce: bytes) -> bool:
    """Verify the DLEQ binding N to C's hidden root, at a fresh (epoch, nonce). Any mismatch → False.
    Returns True only if N genuinely uses the same root committed in C (so you can't present a valid
    C with a nullifier for a different/forged root, e.g. to dodge a block)."""
    if pf.epoch != expected_epoch or pf.nonce != expected_nonce:
        return False                                   # freshness / replay: verifier-issued epoch+nonce
    if not all(_in_subgroup(v) for v in (pf.C, pf.N, pf.T_C, pf.T_N)):
        return False                                   # subgroup membership (no small-subgroup smuggling)
    B = scope_generator(pf.scope)
    e = _challenge(pf.C, pf.N, B, pf.T_C, pf.T_N, pf.scope, pf.epoch, pf.nonce)
    if (pow(G, pf.z_x, P) * pow(Hh, pf.z_s, P)) % P != (pf.T_C * pow(pf.C, e, P)) % P:
        return False                                   # C = G^x·Hh^s branch
    if pow(B, pf.z_x, P) != (pf.T_N * pow(pf.N, e, P)) % P:
        return False                                   # N = B^x branch (same x)
    return True
