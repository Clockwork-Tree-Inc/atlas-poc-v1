"""Revocable anonymous credentials — one zero-knowledge showing that proves, together and unlinkably:
(1) you hold a valid credential for `claim` (hiding your master secret and your revocation handle), and
(2) that SAME handle is still in the issuer's accumulator (not revoked).

Composition of the PS credential proof (ps_credential) and the accumulator membership proof
(anon_revocation), bound by a SHARED Fiat-Shamir challenge and a SINGLE shared response for the handle.
Because the handle response `z_handle` must satisfy BOTH the credential equation (where the handle is a
signed hidden attribute) and the membership equation (where the handle is the accumulated element), the
two are forced equal — so you can only pass with YOUR credential's own handle and its witness.

CROSS-LANGUAGE PORTABLE: like the base PS proof, the two Schnorr commitments are sent as GROUP elements
(Rps in G2, Rmem in G1) and hashed; GT never enters the challenge, so the proof is byte-identical across
the py_ecc reference and the blst on-device port. Messages: [claim, master_secret, handle].
"""
from __future__ import annotations

from dataclasses import dataclass

from .ps_credential import (
    G1, G2, R, Signature, _hash_to_scalar, _pk_bytes, _rand, _ser_g1, _ser_g2, _valid_g1, _valid_g2,
    add, msg_scalar, multiply, pairing, ps_keygen, ps_sign,
)

CLAIM, MASTER, HANDLE = 0, 1, 2


def new_issuer():
    """A revocable-credential issuer: a PS keypair over 3 messages [claim, master_secret, handle]."""
    return ps_keygen(3)


def issue(issuer, *, claim: str, master_secret: int, handle: int) -> Signature:
    """Issue a revocable credential binding the claim, your master secret, and a revocation handle."""
    return ps_sign(issuer, [msg_scalar(claim), master_secret % R, handle % R])


@dataclass
class RevocableProof:
    s1: tuple
    s2: tuple
    wbar: tuple            # blinded witness (G1)
    r_ps: tuple            # credential Schnorr commitment (G2)
    r_mem: tuple           # membership Schnorr commitment (G1)
    c: int
    z_ms: int
    z_handle: int          # SHARED between the credential proof and the membership proof (the binding)
    z_t: int
    z_rho: int


def _transcript(cred_pk, s1, s2, wbar, r_ps, r_mem, claim, nonce) -> int:
    # G1/G2 + scalars only -> byte-identical across py_ecc and blst.
    return _hash_to_scalar(b"atlas/anon-revocable/v1", _pk_bytes(cred_pk), _ser_g1(s1), _ser_g1(s2),
                           _ser_g1(wbar), _ser_g2(r_ps), _ser_g1(r_mem),
                           (msg_scalar(claim) % R).to_bytes(32, "big"), nonce)


def present(cred_pk, credential: Signature, acc_pub: tuple, accumulator: tuple, *, claim: str,
            master_secret: int, handle: int, witness: tuple, nonce: bytes) -> RevocableProof:
    """One unlinkable ZK showing: valid credential for `claim` AND its handle is non-revoked."""
    Yt = cred_pk.Yt
    r, t = _rand(), _rand()
    s1 = multiply(credential[0], r)
    s2 = add(multiply(credential[1], r), multiply(s1, t))       # re-randomised PS signature
    rho = _rand()
    wbar = multiply(witness, rho)                               # re-randomised witness

    rho_ms, k_handle, rho_t, k_rho = _rand(), _rand(), _rand(), _rand()
    # credential commitment R_ps (G2) = g2^{rho_t} * Y~_ms^{rho_ms} * Y~_handle^{k_handle}
    r_ps = multiply(G2, rho_t)
    r_ps = add(r_ps, multiply(Yt[MASTER], rho_ms))
    r_ps = add(r_ps, multiply(Yt[HANDLE], k_handle))
    # membership commitment R_mem (G1) = k_handle * w̄ + k_rho * Acc  (SAME k_handle -> binds the handle)
    r_mem = add(multiply(wbar, k_handle), multiply(accumulator, k_rho))

    c = _transcript(cred_pk, s1, s2, wbar, r_ps, r_mem, claim, nonce)
    return RevocableProof(
        s1=s1, s2=s2, wbar=wbar, r_ps=r_ps, r_mem=r_mem, c=c,
        z_ms=(rho_ms + c * (master_secret % R)) % R,
        z_handle=(k_handle + c * (handle % R)) % R,            # shared response
        z_t=(rho_t + c * t) % R,
        z_rho=(k_rho + c * ((R - (rho % R)) % R)) % R,
    )


def verify(cred_pk, acc_pub: tuple, accumulator: tuple, proof: RevocableProof, *, claim: str,
           nonce: bytes) -> bool:
    """Verify the combined showing: valid credential for `claim` AND non-revoked, one challenge, one
    shared handle response. Learns nothing about master secret, handle, or witness."""
    if not (_valid_g1(proof.s1) and _valid_g1(proof.s2) and _valid_g1(proof.wbar)
            and _valid_g1(proof.r_mem) and _valid_g1(accumulator) and _valid_g2(proof.r_ps)):
        return False
    Yt = cred_pk.Yt
    c = proof.c
    if _transcript(cred_pk, proof.s1, proof.s2, proof.wbar, proof.r_ps, proof.r_mem, claim, nonce) != c:
        return False

    # (1) credential: e(s1, R_ps) == e(s1, W_ps) * target^{-c}, target = e(s2,g2)*e(s1,kappa_pub)^{-1}
    kappa_pub = add(cred_pk.Xt, multiply(Yt[CLAIM], msg_scalar(claim) % R))
    target = pairing(G2, proof.s2) * (pairing(kappa_pub, proof.s1) ** (R - 1))
    w_ps = multiply(G2, proof.z_t)
    w_ps = add(w_ps, multiply(Yt[MASTER], proof.z_ms))
    w_ps = add(w_ps, multiply(Yt[HANDLE], proof.z_handle))
    if pairing(proof.r_ps, proof.s1) != pairing(w_ps, proof.s1) * (target ** ((R - c) % R)):
        return False

    # (2) membership: e(R_mem, g2) == e(z_handle*w̄ + z_rho*Acc, g2) * e(c*w̄, P)
    m = add(multiply(proof.wbar, proof.z_handle % R), multiply(accumulator, proof.z_rho % R))
    n = multiply(proof.wbar, c % R)
    return pairing(G2, proof.r_mem) == pairing(G2, m) * pairing(acc_pub, n)
