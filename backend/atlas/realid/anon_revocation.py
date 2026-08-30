"""Anonymous revocation — a bilinear-map accumulator so a credential can be revoked across ALL personas
at once, without a phone-home and without the verifier learning which credential is being shown.

Why an accumulator (not a list): normal revocation publishes a set of revoked ids and the verifier looks
the credential up. That cannot work with anonymous credentials — the verifier never sees WHICH credential
is presented, so there's nothing to look up. An accumulator inverts it: the issuer publishes ONE value
summarising all the STILL-VALID credentials, and the holder proves "mine is in that set" as part of the
showing. Revoke one credential -> the accumulator changes -> that credential's membership check fails
everywhere at once, while every other credential's keeps working.

Construction (Nguyen / Camenisch-Lysyanskaya bilinear accumulator on BLS12-381, the family AnonCreds
uses). The issuer holds a secret alpha and publishes P = g2^alpha. Each credential carries a revocation
handle id_j (a field element). For a set S of non-revoked handles:

    Acc      = g1^{ prod_{i in S} (alpha + id_i) }              (issuer computes with alpha; public value)
    witness  = w_j = g1^{ prod_{i in S, i != j} (alpha + id_i) } (a member's non-revocation witness)
    check    : e( w_j , g2^alpha * g2^{id_j} ) == e( Acc , g2 )  (PUBLIC — no alpha needed to verify)

Revoke handle k: the issuer recomputes Acc over S minus {k}; the removed handle's witness no longer
satisfies the check, and remaining members refresh their witness.

The unlinkable ZK membership proof keeps the Fiat-Shamir challenge over G1/G2 elements only (its Schnorr
commitment is a G1 element Rg1 with e(Rg1, g2) equal to the classic GT commitment), so it is byte-
identical across the py_ecc reference and the blst on-device port, and the pairing relation is checked as
a representation-independent equality.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List

from .ps_credential import (
    G1, G2, R, _hash_to_scalar, _rand, _ser_g1, _ser_g2, _valid_g1, add, multiply, pairing,
)


def revocation_handle(seed: bytes) -> int:
    """A credential's revocation handle as a field element (the accumulated element)."""
    return _hash_to_scalar(b"atlas/anon-revoc/handle/v1", seed)


@dataclass
class RevocationRegistry:
    """Issuer-side revocation authority. Holds the accumulator secret `alpha`; publishes `pub = g2^alpha`
    and the current accumulator. `members` is the set of non-revoked handles."""
    alpha: int
    pub: tuple                                  # g2^alpha (G2) — public
    members: List[int] = field(default_factory=list)

    @staticmethod
    def new() -> "RevocationRegistry":
        alpha = _rand()
        return RevocationRegistry(alpha=alpha, pub=multiply(G2, alpha))

    def _acc_over(self, handles: Iterable[int]) -> tuple:
        exp = 1
        for h in handles:
            exp = (exp * ((self.alpha + h) % R)) % R
        return multiply(G1, exp)

    def add_member(self, handle: int) -> None:
        if handle % R not in [m % R for m in self.members]:
            self.members.append(handle % R)

    def accumulator(self) -> tuple:
        """The published value summarising all non-revoked handles."""
        return self._acc_over(self.members)

    def witness(self, handle: int) -> tuple:
        """A member's non-revocation witness — the accumulator over everyone BUT them."""
        h = handle % R
        if h not in [m % R for m in self.members]:
            raise ValueError("handle is not an accumulated member")
        return self._acc_over([m for m in self.members if m % R != h])

    def revoke(self, handle: int) -> None:
        """Remove a handle. After this, its witness fails the check and the accumulator changes; other
        members refresh via `witness` against the new set."""
        h = handle % R
        self.members = [m for m in self.members if m % R != h]


def verify_membership(pub: tuple, accumulator: tuple, *, handle: int, witness: tuple) -> bool:
    """PUBLIC check (no alpha): is `handle` still accumulated? e(w, g2^alpha * g2^{id}) == e(Acc, g2).
    Fail-closed on a malformed witness. Reveals the handle+witness — LINKABLE; use the ZK form below
    for unlinkable revocation checking."""
    if not _valid_g1(witness) or not _valid_g1(accumulator):
        return False
    lhs = pairing(add(pub, multiply(G2, handle % R)), witness)
    rhs = pairing(G2, accumulator)
    return lhs == rhs


# --- unlinkable zero-knowledge membership proof (cross-language portable) ---------------------------
# From w^{alpha+id} = Acc, blind the witness wbar = w^rho, so e(wbar, P*g2^{id}) = e(Acc, g2)^rho, which
# rearranges to the two-secret DL statement B1^{id} * B2^{-rho} = target with B1=e(wbar,g2),
# B2=e(Acc,g2), target=e(wbar,P)^{-1}. The Schnorr commitment B1^k1*B2^k2 equals e(Rg1, g2) for the G1
# element Rg1 = k1*wbar + k2*Acc, so we send Rg1 (a portable G1 element), hash G1/G2 only, and check the
# pairing relation as a representation-independent equality.

@dataclass
class MembershipProof:
    wbar: tuple          # w^rho (blinded witness, fresh per showing) — G1
    commitment: tuple    # Schnorr commitment Rg1 in G1 (portable; keeps GT out of the hash)
    c: int
    z_id: int            # Schnorr response for the hidden handle
    z_rho: int           # Schnorr response for the blinding (exponent -rho)


def _mem_challenge(pub, accumulator, wbar, commitment, nonce) -> int:
    return _hash_to_scalar(b"atlas/anon-revoc-zk/v1", _ser_g2(pub), _ser_g1(accumulator),
                           _ser_g1(wbar), _ser_g1(commitment), nonce)


def prove_membership(pub: tuple, accumulator: tuple, *, handle: int, witness: tuple,
                     nonce: bytes) -> MembershipProof:
    """Holder side: an unlinkable ZK proof that `handle` (hidden) is accumulated, using `witness`."""
    rho = _rand()
    wbar = multiply(witness, rho)
    k1, k2 = _rand(), _rand()
    Rg1 = add(multiply(wbar, k1), multiply(accumulator, k2))     # k1*wbar + k2*Acc (G1)
    c = _mem_challenge(pub, accumulator, wbar, Rg1, nonce)
    z_id = (k1 + c * (handle % R)) % R
    z_rho = (k2 + c * ((R - (rho % R)) % R)) % R                 # exponent for B2 is -rho
    return MembershipProof(wbar=wbar, commitment=Rg1, c=c, z_id=z_id, z_rho=z_rho)


def verify_membership_zk(pub: tuple, accumulator: tuple, proof: MembershipProof, nonce: bytes) -> bool:
    """Verifier side: check the ZK membership proof against the REAL public accumulator. Learns neither
    the handle nor the witness; fail-closed on malformed input."""
    if not (_valid_g1(proof.wbar) and _valid_g1(proof.commitment) and _valid_g1(accumulator)):
        return False
    c = proof.c
    if _mem_challenge(pub, accumulator, proof.wbar, proof.commitment, nonce) != c:
        return False
    # e(Rg1, g2) == e(z_id*wbar + z_rho*Acc, g2) * e(c*wbar, P)
    M = add(multiply(proof.wbar, proof.z_id % R), multiply(accumulator, proof.z_rho % R))
    N = multiply(proof.wbar, c % R)
    lhs = pairing(G2, proof.commitment)
    rhs = pairing(G2, M) * pairing(pub, N)
    return lhs == rhs
