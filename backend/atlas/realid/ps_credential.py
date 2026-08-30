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
    FQ, FQ2, G1, G2, add, b, b2, curve_order, is_inf, is_on_curve, multiply, normalize, pairing,
)

R = curve_order


def msg_scalar(s: str) -> int:
    """Map a credential attribute STRING (as BBS+ uses) to a field element, so the
    PS backend signs/reveals the exact same [claim, level, system-id] attributes."""
    return _hash_to_scalar(b"atlas/ps-msg", s.encode("utf-8"))


def _rand() -> int:
    return 1 + secrets.randbelow(R - 1)


def _hash_to_scalar(*chunks: bytes) -> int:
    # wide reduction (RFC 9380 hash-to-field style): hash to 512 bits then reduce mod R, so the
    # modular bias is negligible (< 2^-256) instead of ~1 bit with a 256-bit digest.
    h = hashlib.sha512()
    for c in chunks:
        h.update(len(c).to_bytes(4, "big"))
        h.update(c)
    return int.from_bytes(h.digest(), "big") % R


def _ser_g1(pt) -> bytes:
    x, y = normalize(pt)
    return int(x).to_bytes(48, "big") + int(y).to_bytes(48, "big")


def _ser_gt(gt) -> bytes:
    return b"".join(int(c).to_bytes(48, "big") for c in gt.coeffs)


def _ser_g2(pt) -> bytes:
    x, y = normalize(pt)
    return b"".join(int(c).to_bytes(48, "big") for c in (*x.coeffs, *y.coeffs))


def _pk_bytes(pk: "PSPublicKey") -> bytes:
    """Bind the issuer public key into the Fiat–Shamir challenge (total-binding FS): the challenge
    covers X~, every Y~_i, and n — so a proof can't be reinterpreted under a different issuer key."""
    return _ser_g2(pk.Xt) + b"".join(_ser_g2(y) for y in pk.Yt) + pk.n.to_bytes(4, "big")


# --------------------------------------------------------------------------- keys
@dataclass
class PSPublicKey:
    Xt: tuple                     # g2^x (G2)
    Yt: Tuple[tuple, ...]         # g2^{y_i} (G2), one per message
    n: int
    Yg1: Tuple[tuple, ...] = ()   # g1^{y_i} (G1), one per message — bases for blind-issuance commitments


@dataclass
class PSSecretKey:
    x: int
    y: Tuple[int, ...]
    public: PSPublicKey


def ps_keygen(n_messages: int) -> PSSecretKey:
    x = _rand()
    ys = tuple(_rand() for _ in range(n_messages))
    pk = PSPublicKey(Xt=multiply(G2, x), Yt=tuple(multiply(G2, y) for y in ys), n=n_messages,
                     Yg1=tuple(multiply(G1, y) for y in ys))
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


# --------------------------------------------------------------- blind issuance
# PS blind signature: the issuer signs [disclosed | hidden] messages WITHOUT seeing the hidden ones.
# The holder sends a commitment C = g1^t * prod_{i in hidden} Yg1_i^{m_i} with a Schnorr PoK; the issuer
# folds in its secret and the disclosed messages homomorphically; the holder unblinds to a STANDARD PS
# signature on all messages. Output is verifiable/presentable by ps_present/ps_verify unchanged.

@dataclass
class BlindRequest:
    C: tuple                                # commitment in G1
    hidden_idx: Tuple[int, ...]             # indices committed inside C (sorted)
    proof: Tuple[int, Tuple[int, ...]]      # Schnorr PoK (challenge, responses) over (g1, Yg1_hidden)


def _multibase(bases, scalars):
    """prod bases_j^{scalars_j} in G1."""
    acc = None
    for B, s in zip(bases, scalars):
        term = multiply(B, s % R)
        acc = term if acc is None else add(acc, term)
    return acc


def _pok_ctx(pk: PSPublicKey, bases) -> bytes:
    return _pk_bytes(pk) + b"".join(_ser_g1(B) for B in bases)


def _schnorr_prove(bases, secrets, C, ctx: bytes):
    ks = [_rand() for _ in bases]
    A = _multibase(bases, ks)
    c = _hash_to_scalar(b"atlas/ps-blind-pok/v1", ctx, _ser_g1(C), _ser_g1(A))
    z = tuple((k + c * (s % R)) % R for k, s in zip(ks, secrets))
    return (c, z)


def _schnorr_verify(bases, C, proof, ctx: bytes) -> bool:
    c, z = proof
    if len(z) != len(bases):
        return False
    # A' = prod bases^z * C^{-c}  (== A iff z_j = k_j + c*secret_j)
    Ap = add(_multibase(bases, z), multiply(C, (R - (c % R)) % R))
    return _hash_to_scalar(b"atlas/ps-blind-pok/v1", ctx, _ser_g1(C), _ser_g1(Ap)) == c


def _pok_bases(pk: PSPublicKey, hidden_idx):
    return [G1] + [pk.Yg1[i] for i in hidden_idx]


def blind_request(pk: PSPublicKey, hidden: dict) -> Tuple[BlindRequest, int]:
    """Holder side: commit to the HIDDEN messages {idx: scalar} and prove knowledge. Returns the request
    to send the issuer and the blinding `t` to KEEP for unblinding (never sent)."""
    hidden_idx = tuple(sorted(hidden))
    t = _rand()
    bases = _pok_bases(pk, hidden_idx)
    secrets = [t] + [hidden[i] % R for i in hidden_idx]
    C = _multibase(bases, secrets)
    return BlindRequest(C=C, hidden_idx=hidden_idx, proof=_schnorr_prove(bases, secrets, C, _pok_ctx(pk, bases))), t


def blind_sign(sk: PSSecretKey, req: BlindRequest, disclosed: dict) -> Signature:
    """Issuer side: verify the PoK, then blind-sign. `disclosed` = {idx: scalar} for the messages the
    issuer sees; with req.hidden_idx these must cover 0..n-1 exactly. The issuer never learns the hidden
    scalars. Returns a BLINDED signature (s1', s2'); the holder unblinds with `blind_unblind`."""
    pk = sk.public
    if not _valid_g1(req.C):
        raise ValueError("commitment not a valid group element")
    if set(req.hidden_idx) & set(disclosed):
        raise ValueError("an index is both hidden and disclosed")
    if set(req.hidden_idx) | set(disclosed) != set(range(pk.n)):
        raise ValueError("hidden + disclosed must cover all messages exactly")
    bases = _pok_bases(pk, req.hidden_idx)
    if not _schnorr_verify(bases, req.C, req.proof, _pok_ctx(pk, bases)):
        raise ValueError("commitment proof invalid")
    u = _rand()
    acc = add(multiply(G1, sk.x), req.C)                       # g1^x * C
    for i, m in disclosed.items():
        acc = add(acc, multiply(pk.Yg1[i], m % R))            # * prod_disclosed Yg1_i^{m_i}
    return (multiply(G1, u), multiply(acc, u))                 # (g1^u, acc^u)


def blind_unblind(blinded: Signature, t: int) -> Signature:
    """Holder side: strip the blinding -> a standard PS signature on ALL messages (s2 = s2' * s1'^{-t})."""
    s1p, s2p = blinded
    return (s1p, add(s2p, multiply(s1p, (R - (t % R)) % R)))


# --------------------------------------------------------------------------- present
@dataclass
class PSProof:
    s1: tuple
    s2: tuple
    commitment: tuple                 # Schnorr commitment R in G2 (portable; keeps GT out of the hash)
    reveal: Tuple[int, ...]           # revealed indices (sorted)
    revealed_vals: Tuple[int, ...]    # revealed message scalars (same order as reveal)
    responses: Tuple[int, ...]        # Schnorr responses: hidden msgs (index order) then t
    challenge: int


def _transcript(s1, s2, commitment, reveal, revealed_vals, nonce) -> bytes:
    # Hashes ONLY G1/G2 elements (s1, s2, R) + scalars — all byte-identical across py_ecc and blst — so
    # the Fiat-Shamir challenge matches cross-language. GT never enters the hash (it is representation-
    # dependent); the pairing relation is checked as a representation-independent equality at verify time.
    parts = [_ser_g1(s1), _ser_g1(s2), _ser_g2(commitment), nonce]
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

    # Commitment R in G2: g2^rho_t * prod_hidden Y~_i^{rho_i}. Then e(s1,R) equals the GT commitment of
    # the classic proof, but R itself is a portable G2 element we can hash.
    rho = [_rand() for _ in hidden]
    rho_t = _rand()
    Rc = multiply(G2, rho_t)
    for i, rr in zip(hidden, rho):
        Rc = add(Rc, multiply(pk.Yt[i], rr))

    revealed_vals = tuple(messages[i] % R for i in reveal)
    c = _hash_to_scalar(b"atlas/ps-cred/v1", _pk_bytes(pk), _transcript(s1, s2, Rc, reveal, revealed_vals, nonce))
    resp = [(rr + c * (messages[i] % R)) % R for i, rr in zip(hidden, rho)]
    resp_t = (rho_t + c * t) % R
    return PSProof(s1=s1, s2=s2, commitment=Rc, reveal=reveal, revealed_vals=revealed_vals,
                   responses=tuple(resp + [resp_t]), challenge=c)


# --------------------------------------------------------------------------- verify
def _valid_g1(pt) -> bool:
    """A RECEIVED G1 point (attacker-supplied in a proof) must be on-curve AND in the prime-order-R
    subgroup — else a malicious prover could smuggle an off-curve or small-subgroup component past
    the pairing checks (subgroup confusion). Fail closed on any malformed input."""
    try:
        if is_inf(pt) or not is_on_curve(pt, b):
            return False
        return is_inf(multiply(pt, R))          # prime-order subgroup membership: R*pt == O
    except Exception:
        return False


def _valid_g2(pt) -> bool:
    """As _valid_g1, for a received G2 element (the proof's commitment)."""
    try:
        if is_inf(pt) or not is_on_curve(pt, b2):
            return False
        return is_inf(multiply(pt, R))
    except Exception:
        return False


def ps_verify(pk: PSPublicKey, proof: PSProof, nonce: bytes) -> bool:
    if not (_valid_g1(proof.s1) and _valid_g1(proof.s2)):
        return False
    reveal = proof.reveal
    if any(i < 0 or i >= pk.n for i in reveal) or len(set(reveal)) != len(reveal):
        return False                                       # fail closed on out-of-range / duplicate indices
    hidden = [i for i in range(pk.n) if i not in reveal]
    if len(proof.responses) != len(hidden) + 1 or len(proof.revealed_vals) != len(reveal):
        return False
    if not _valid_g2(proof.commitment):
        return False
    *resp, resp_t = proof.responses
    c = proof.challenge

    # (1) Fiat-Shamir: the challenge must be the hash of the sent commitment R (binds R). Portable.
    c2 = _hash_to_scalar(b"atlas/ps-cred/v1", _pk_bytes(pk),
                         _transcript(proof.s1, proof.s2, proof.commitment, reveal, proof.revealed_vals, nonce))
    if c2 != c:
        return False

    # (2) Pairing relation (representation-independent equality): e(s1, R) == e(s1, W) * target^{-c},
    # where target = e(s2,g2)*e(s1,kappa_pub)^{-1} and W = g2^{s_t} * prod_hidden Y~_i^{s_i}.
    kappa_pub = pk.Xt
    for i, m in zip(reveal, proof.revealed_vals):
        kappa_pub = add(kappa_pub, multiply(pk.Yt[i], m % R))
    target = pairing(G2, proof.s2) * (pairing(kappa_pub, proof.s1) ** (R - 1))
    W = multiply(G2, resp_t)
    for i, s in zip(hidden, resp):
        W = add(W, multiply(pk.Yt[i], s))
    lhs = pairing(proof.commitment, proof.s1)
    rhs = pairing(W, proof.s1) * (target ** ((R - c) % R))
    return lhs == rhs


# --------------------------------------------------------------------------- serialize
def _g1_from_bytes(b: bytes):
    x = int.from_bytes(b[:48], "big")
    y = int.from_bytes(b[48:96], "big")
    return (FQ(x), FQ(y), FQ.one())


def _g2_from_bytes(bb: bytes):
    x = FQ2([int.from_bytes(bb[0:48], "big"), int.from_bytes(bb[48:96], "big")])
    y = FQ2([int.from_bytes(bb[96:144], "big"), int.from_bytes(bb[144:192], "big")])
    return (x, y, FQ2.one())


def serialize_proof(p: PSProof) -> bytes:
    """Opaque proof bytes (for InheritedProof.proof). Excludes revealed_vals — the
    verifier reconstructs those from the revealed attribute strings, binding the proof
    to the claimed messages. Fresh per presentation (s1/s2/challenge randomised)."""
    out = _ser_g1(p.s1) + _ser_g1(p.s2) + _ser_g2(p.commitment)
    out += len(p.reveal).to_bytes(2, "big") + b"".join(i.to_bytes(2, "big") for i in p.reveal)
    out += len(p.responses).to_bytes(2, "big") + b"".join((r % R).to_bytes(32, "big") for r in p.responses)
    out += (p.challenge % R).to_bytes(32, "big")
    return out


def deserialize_proof(b: bytes, revealed_vals: Sequence[int]) -> PSProof:
    s1 = _g1_from_bytes(b[0:96])
    s2 = _g1_from_bytes(b[96:192])
    commitment = _g2_from_bytes(b[192:384])
    o = 384
    nr = int.from_bytes(b[o:o + 2], "big"); o += 2
    reveal = tuple(int.from_bytes(b[o + 2 * k:o + 2 * k + 2], "big") for k in range(nr)); o += 2 * nr
    ns = int.from_bytes(b[o:o + 2], "big"); o += 2
    responses = tuple(int.from_bytes(b[o + 32 * k:o + 32 * k + 32], "big") for k in range(ns)); o += 32 * ns
    challenge = int.from_bytes(b[o:o + 32], "big")
    return PSProof(s1=s1, s2=s2, commitment=commitment, reveal=reveal,
                   revealed_vals=tuple(v % R for v in revealed_vals),
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
    bad = PSProof(p1.s1, p1.s2, p1.commitment, p1.reveal, (p1.revealed_vals[0], 9), p1.responses, p1.challenge)
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
