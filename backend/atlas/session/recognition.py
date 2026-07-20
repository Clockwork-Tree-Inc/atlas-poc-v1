"""Recognition and the evolving tunnel (§4).

  recognition       = HKDF( SessionKey_1, SessionKey_2, beacon )         [§4]
  tunnel_key[next]  = HKDF( tunnel_key[prev], recognition[this_epoch] )  [§4]

"Only something holding both live session keys can produce the recognition
value; neither key crosses the wire (each side combines its own session key with
the other's public contribution plus the beacon, key-agreement style, re-run
every epoch)."

Realisation: each device derives a per-epoch X25519 ephemeral keypair *from its
own session key*; the public halves are the contributions exchanged on the wire.
The beacon is folded in so recognition advances when the beacon advances.

HONEST threat boundary (corrected after review — see
tests/test_security_properties.py): this is a Diffie-Hellman-style agreement.
The provable property is OUTSIDER resistance — a party with NEITHER session key
cannot compute recognition. The quoted spec phrasing ("only something holding
BOTH live session keys") overstates it: EITHER endpoint's session key plus the
public wire traffic reconstructs the tunnel. That is the normal bound for
2-party agreement (compromising an endpoint compromises its pairwise tunnel),
and is exactly what forward secrecy + epoch re-keying exist to contain.

Symmetric rooting (§3.2 decision #2): both contributions enter the HKDF in a
canonical (sorted) order, so neither device leads.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from ..crypto.primitives import hkdf, hkdf_combine
from ..params import CONTEXT_RECOGNITION, CONTEXT_TUNNEL


@dataclass(frozen=True)
class RecognitionContribution:
    """The public, on-the-wire half of a device's per-epoch contribution."""

    public: bytes  # raw X25519 public key derived from the session key


def _epoch_ephemeral(session_key: bytes, beacon: bytes) -> X25519PrivateKey:
    # Deterministically derive a per-epoch X25519 private key from the session
    # key (so the contribution is a function of the live session key) and the
    # beacon (so it rotates each epoch).
    seed = hkdf(ikm=session_key, info=CONTEXT_RECOGNITION + b"|eph|" + beacon, length=32)
    return X25519PrivateKey.from_private_bytes(seed)


def contribution(session_key: bytes, beacon: bytes) -> tuple[X25519PrivateKey, RecognitionContribution]:
    priv = _epoch_ephemeral(session_key, beacon)
    pub = priv.public_key().public_bytes_raw()
    return priv, RecognitionContribution(public=pub)


def recognition_value(
    *, my_priv: X25519PrivateKey, their_pub: bytes, my_pub: bytes, beacon: bytes
) -> bytes:
    """Compute the shared recognition value (identical on both devices)."""
    shared = my_priv.exchange(X25519PublicKey.from_public_bytes(their_pub))
    # Canonical (sorted) ordering => symmetric: neither device leads.
    a, b = sorted([my_pub, their_pub])
    return hkdf_combine([shared, a, b, beacon], info=CONTEXT_RECOGNITION, length=32)


def evolve_tunnel_key(prev_tunnel_key: bytes, recognition: bytes) -> bytes:
    """tunnel_key[next] = HKDF(tunnel_key[prev], recognition[this_epoch]) (§4).

    Every re-recognition is a re-key; a captured tunnel key dies at the next
    beacon advance."""
    return hkdf_combine([prev_tunnel_key, recognition], info=CONTEXT_TUNNEL, length=32)


# ---------------------------------------------------------------------------
# Hybrid PQ recognition — ML-KEM-768 + X25519 (Credential PQC Posture: unify the
# core tunnel to the same post-quantum hybrid as the credential channel).
#
# A symmetric two-encapsulation handshake: each side derives its X25519 half from
# the live session key (binds the session key, as before) AND generates an
# ephemeral ML-KEM keypair. Each encapsulates to the OTHER's ML-KEM key; both
# exchange ciphertexts and decapsulate. The recognition mixes the X25519 DH with
# BOTH ML-KEM shared secrets, so a quantum adversary must break ML-KEM to recover
# the tunnel even with the classical X25519 transcript (harvest-now-decrypt-later
# resistant). Ephemeral ML-KEM keypairs also give the PQ part forward secrecy.
# ---------------------------------------------------------------------------

from kyber_py.ml_kem import ML_KEM_768  # noqa: E402


@dataclass(frozen=True)
class HybridContribution:
    """Public on-the-wire half: X25519 public (session-key-bound) + ML-KEM EK."""

    x25519_pub: bytes
    mlkem_ek: bytes


def hybrid_contribution(session_key: bytes, beacon: bytes):
    """Return (x25519_priv, mlkem_dk, HybridContribution). X25519 is derived from
    the session key; ML-KEM is a fresh ephemeral keypair."""
    x_priv = _epoch_ephemeral(session_key, beacon)
    mlkem_ek, mlkem_dk = ML_KEM_768.keygen()
    pub = HybridContribution(x25519_pub=x_priv.public_key().public_bytes_raw(), mlkem_ek=mlkem_ek)
    return x_priv, mlkem_dk, pub


def hybrid_encapsulate(their: HybridContribution) -> tuple[bytes, bytes]:
    """Encapsulate to the peer's ML-KEM key. Returns (ciphertext, shared_secret)."""
    ss, ct = ML_KEM_768.encaps(their.mlkem_ek)
    return ct, ss


def hybrid_recognition_value(*, my_x_priv: X25519PrivateKey, my_mlkem_dk: bytes,
                             my_pub: HybridContribution, their_pub: HybridContribution,
                             their_ct: bytes, my_ss_self: bytes, beacon: bytes) -> bytes:
    """Combine X25519 DH + BOTH ML-KEM shared secrets into the recognition value.
    Identical on both devices."""
    x_dh = my_x_priv.exchange(X25519PublicKey.from_public_bytes(their_pub.x25519_pub))
    ss_peer = ML_KEM_768.decaps(my_mlkem_dk, their_ct)
    ss_lo, ss_hi = sorted([my_ss_self, ss_peer])           # canonical: neither leads
    pub_lo, pub_hi = sorted([my_pub.x25519_pub, their_pub.x25519_pub])
    return hkdf_combine([x_dh, ss_lo, ss_hi, pub_lo, pub_hi, beacon],
                        info=CONTEXT_RECOGNITION + b"/hybrid", length=32)
