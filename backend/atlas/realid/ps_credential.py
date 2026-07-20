"""Pointcheval-Sanders anonymous credential — a pure-Python, always-installable
backend so the unlinkable verification-inheritance path RUNS everywhere (CI, Apple
Silicon) instead of depending on the archived Ursa BBS+ native library.

This is a GENUINE anonymous credential (not the Mock): re-randomized PS signatures
plus a Schnorr proof of knowledge for selective disclosure. Two presentations of one
credential are unlinkable, and hidden attributes are not recoverable from a proof.

Classical pairing crypto on BLS12-381 (same posture as BBS+ — see verification.py's
HONEST BOUNDS: not post-quantum; a PQ anonymous credential is the open north star).
Correctness + portability over speed: this is the reference backend, native libs are a
performance-only swap behind the same CredentialScheme seam.

Construction (Pointcheval-Sanders, multi-message):
  sk = (x, y_0..y_{n-1});  pk = (X~=g2^x, Y~_i=g2^{y_i})
  sign(m):    u<-Zr; s1=g1^u; s2=s1^{x+sum y_i m_i}
  present:    re-randomize (s1'=s1^r, s2'=s2^r * s1'^t) then a Schnorr PoK over GT of
              the HIDDEN messages + t, revealing the rest. Relation:
                e(s1', X~ * prod Y~_i^{m_i} * g2^t) = e(s2', g2)
  verify:     recompute the Fiat-Shamir challenge from the same transcript.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import List, Sequence, Tuple

from py_ecc.optimized_bls12_381 import (
    FQ, G1, G2, add, curve_order, is_inf, multiply, normalize, pairing,
)

R = curve_order


def msg_scalar(s: str) -> int:
    """Map a credential attribute STRING (as BBS+ uses) to a field element, so the
    PS backend signs/reveals the exact same [claim, level, system-id] attributes."""
    return _hash_to_scalar(b"atlas/ps-msg", s.encode("utf-8"))


def _rand() -> int:
    return 1 + secrets.randbelow(R - 1)


def _hash_to_scalar(*chunks: bytes) -> int:
    h = hashlib.sha256()
    for c in chunks:
        h.update(len(c).to_bytes(4, "big"))
        h.update(c)
    return int.from_bytes(h.digest(), "big") % R


def _ser_g1(pt) -> bytes:
    x, y = normalize(pt)
    return int(x).to_bytes(48, "big") + int(y).to_bytes(48, "big")


def _ser_gt(gt) -> bytes:
    return b"".join(int(c).to_bytes(48, "big") for c in gt.coeffs)


# --------------------------------------------------------------------------- keys
@dataclass
class PSPublicKey:
    Xt: tuple                     # g2^x (G2)
    Yt: Tuple[tuple, ...]         # g2^{y_i} (G2), one per message
    n: int


@dataclass
class PSSecretKey:
    x: int
    y: Tuple[int, ...]
    public: PSPublicKey


def ps_keygen(n_messages: int) -> PSSecretKey:
    x = _rand()
    ys = tuple(_rand() for _ in range(n_messages))
    pk = PSPublicKey(Xt=multiply(G2, x), Yt=tuple(multiply(G2, y) for y in ys), n=n_messages)
    return PSSecretKey(x=x, y=ys, public=pk)


# --------------------------------------------------------------------------- sign
Signature = Tuple[tuple, tuple]   # (s1, s2) in G1


def ps_sign(sk: PSSecretKey, messages: Sequence[int]) -> Signature:
    if len(messages) != sk.public.n:
        raise ValueError("message count mismatch")
    u = _rand()
    s1 = multiply(G1, u)
    e = (sk.x + sum((y * (m % R)) for y, m in zip(sk.y, messages))) % R
    return (s1, multiply(s1, e))


# --------------------------------------------------------------------------- present
@dataclass
class PSProof:
    s1: tuple
    s2: tuple
    reveal: Tuple[int, ...]           # revealed indices (sorted)
    revealed_vals: Tuple[int, ...]    # revealed message scalars (same order as reveal)
    responses: Tuple[int, ...]        # Schnorr responses: hidden msgs (index order) then t
    challenge: int


def _transcript(s1, s2, reveal, revealed_vals, nonce, T) -> bytes:
    parts = [_ser_g1(s1), _ser_g1(s2), nonce, _ser_gt(T)]
    for i, v in zip(reveal, revealed_vals):
        parts.append(i.to_bytes(2, "big"))
        parts.append((v % R).to_bytes(32, "big"))
    return b"".join(parts)


def ps_present(pk: PSPublicKey, sig: Signature, messages: Sequence[int],
               reveal: Sequence[int], nonce: bytes) -> PSProof:
    reveal = tuple(sorted(reveal))
    hidden = [i for i in range(pk.n) if i not in reveal]
    r, t = _rand(), _rand()
    s1 = multiply(sig[0], r)
    s2 = add(multiply(sig[1], r), multiply(s1, t))          # s2' = s2^r * s1'^t

    base_h = [pairing(pk.Yt[i], s1) for i in hidden]         # e(s1, Y~_i)
    base_t = pairing(G2, s1)                                 # e(s1, g2)
    rho = [_rand() for _ in hidden]
    rho_t = _rand()
    T = base_t ** rho_t
    for b, rr in zip(base_h, rho):
        T = T * (b ** rr)

    revealed_vals = tuple(messages[i] % R for i in reveal)
    c = _hash_to_scalar(b"atlas/ps-cred/v1", _transcript(s1, s2, reveal, revealed_vals, nonce, T))
    resp = [(rr + c * (messages[i] % R)) % R for i, rr in zip(hidden, rho)]
    resp_t = (rho_t + c * t) % R
    return PSProof(s1=s1, s2=s2, reveal=reveal, revealed_vals=revealed_vals,
                   responses=tuple(resp + [resp_t]), challenge=c)


# --------------------------------------------------------------------------- verify
def ps_verify(pk: PSPublicKey, proof: PSProof, nonce: bytes) -> bool:
    if is_inf(proof.s1) or is_inf(proof.s2):
        return False
    reveal = proof.reveal
    hidden = [i for i in range(pk.n) if i not in reveal]
    if len(proof.responses) != len(hidden) + 1 or len(proof.revealed_vals) != len(reveal):
        return False
    *resp, resp_t = proof.responses
    c = proof.challenge

    kappa = pk.Xt
    for i, m in zip(reveal, proof.revealed_vals):
        kappa = add(kappa, multiply(pk.Yt[i], m % R))

    # A = e(s1, kappa)^{-1} * e(s2, g2)  == e(s1, prod_hidden Y~_i^{m_i} * g2^t)
    A = (pairing(kappa, proof.s1) ** (R - 1)) * pairing(G2, proof.s2)
    # T' = A^{-c} * e(s1,g2)^{s_t} * prod e(s1,Y~_i)^{s_i}
    Tp = A ** ((R - c) % R)
    Tp = Tp * (pairing(G2, proof.s1) ** resp_t)
    for i, s in zip(hidden, resp):
        Tp = Tp * (pairing(pk.Yt[i], proof.s1) ** s)

    c2 = _hash_to_scalar(b"atlas/ps-cred/v1", _transcript(proof.s1, proof.s2, reveal, proof.revealed_vals, nonce, Tp))
    return c2 == c


# --------------------------------------------------------------------------- serialize
def _g1_from_bytes(b: bytes):
    x = int.from_bytes(b[:48], "big")
    y = int.from_bytes(b[48:96], "big")
    return (FQ(x), FQ(y), FQ.one())


def serialize_proof(p: PSProof) -> bytes:
    """Opaque proof bytes (for InheritedProof.proof). Excludes revealed_vals — the
    verifier reconstructs those from the revealed attribute strings, binding the proof
    to the claimed messages. Fresh per presentation (s1/s2/challenge randomised)."""
    out = _ser_g1(p.s1) + _ser_g1(p.s2)
    out += len(p.reveal).to_bytes(2, "big") + b"".join(i.to_bytes(2, "big") for i in p.reveal)
    out += len(p.responses).to_bytes(2, "big") + b"".join((r % R).to_bytes(32, "big") for r in p.responses)
    out += (p.challenge % R).to_bytes(32, "big")
    return out


def deserialize_proof(b: bytes, revealed_vals: Sequence[int]) -> PSProof:
    s1 = _g1_from_bytes(b[0:96])
    s2 = _g1_from_bytes(b[96:192])
    o = 192
    nr = int.from_bytes(b[o:o + 2], "big"); o += 2
    reveal = tuple(int.from_bytes(b[o + 2 * k:o + 2 * k + 2], "big") for k in range(nr)); o += 2 * nr
    ns = int.from_bytes(b[o:o + 2], "big"); o += 2
    responses = tuple(int.from_bytes(b[o + 32 * k:o + 32 * k + 32], "big") for k in range(ns)); o += 32 * ns
    challenge = int.from_bytes(b[o:o + 32], "big")
    return PSProof(s1=s1, s2=s2, reveal=reveal, revealed_vals=tuple(v % R for v in revealed_vals),
                   responses=responses, challenge=challenge)


# --------------------------------------------------------------------------- self-test
if __name__ == "__main__":
    sk = ps_keygen(3)
    pk = sk.public
    msgs = [_hash_to_scalar(b"atlas-verified"), 1, _hash_to_scalar(b"systemid=deadbeef")]

    sig = ps_sign(sk, msgs)
    # reveal claim(0) + level(1), hide system-id(2)
    p1 = ps_present(pk, sig, msgs, reveal=[0, 1], nonce=b"n1")
    p2 = ps_present(pk, sig, msgs, reveal=[0, 1], nonce=b"n2")
    assert ps_verify(pk, p1, b"n1"), "valid proof must verify"
    assert ps_verify(pk, p2, b"n2"), "valid proof must verify"
    print("correctness: OK")

    # unlinkability: two presentations of the SAME credential are unequal + hidden msg absent
    assert _ser_g1(p1.s1) != _ser_g1(p2.s1) and p1.challenge != p2.challenge, "presentations must differ"
    assert msgs[2] not in p1.revealed_vals and msgs[2] not in p1.responses, "hidden system-id must not leak"
    print("unlinkable + hiding: OK")

    # wrong nonce fails (proof bound to nonce)
    assert not ps_verify(pk, p1, b"WRONG"), "nonce binding must hold"
    # tamper: flip a revealed level -> must fail
    bad = PSProof(p1.s1, p1.s2, p1.reveal, (p1.revealed_vals[0], 9), p1.responses, p1.challenge)
    assert not ps_verify(pk, bad, b"n1"), "tampered reveal must fail"
    # forgery: a proof under a DIFFERENT issuer key must fail
    other = ps_keygen(3).public
    assert not ps_verify(other, p1, b"n1"), "wrong issuer key must fail"
    print("soundness (nonce/tamper/forgery): OK")

    # serialize round-trip: opaque bytes, verifier rebuilds revealed_vals from strings
    blob = serialize_proof(p1)
    rebuilt = deserialize_proof(blob, revealed_vals=[msgs[0], msgs[1]])
    assert ps_verify(pk, rebuilt, b"n1"), "deserialized proof must verify"
    assert msgs[2].to_bytes(32, "big") not in blob, "hidden system-id must not appear in the bytes"
    b2 = serialize_proof(p2)
    assert blob != b2, "serialized presentations must differ (unlinkable on the wire)"
    print("serialize round-trip + wire-unlinkability: OK")
    print("ALL PS SELF-TESTS PASSED")
