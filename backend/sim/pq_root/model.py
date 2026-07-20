"""Model of the PQ root-of-trust custody topology.

All secret material lives in explicit objects so tests can drop/wipe them and
assert what survives. Nothing here is durable state on disk; the point of the
model is to make "who holds what" auditable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from atlas.crypto import kem, primitives, shamir, sign

# The custody factor set: three personal factors + one server-held factor.
FACTORS = ["phone_se", "usb", "yubikey", "server_se"]


# ---------------------------------------------------------------------------
# Holders (each has a hybrid-KEM secure-element keypair)
# ---------------------------------------------------------------------------


@dataclass
class Holder:
    """A share holder: a device / secure element with its own hybrid-KEM key.

    The KEM *secret* (kem_kp.mlkem_dk / x25519_sk) never leaves the holder; it
    is what makes a wrapped share unwrappable only by this holder.
    """

    name: str
    kem_kp: kem.HybridKEMKeypair

    @property
    def public(self) -> kem.HybridKEMPublic:
        return self.kem_kp.public


def make_holders(names: Sequence[str] = FACTORS) -> Dict[str, Holder]:
    return {n: Holder(name=n, kem_kp=kem.generate_keypair()) for n in names}


# ---------------------------------------------------------------------------
# KEM-wrapped shares (transit form)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WrappedShare:
    """A Shamir share sealed to exactly one holder via hybrid KEM + AES-GCM."""

    holder_name: str
    generation: int
    mlkem_ct: bytes
    x_eph_pk: bytes
    aead_blob: bytes


def wrap_share_to(holder: Holder, generation: int, share: shamir.Share) -> WrappedShare:
    enc = kem.encapsulate(holder.public)
    aad = f"{holder.name}|gen{generation}".encode()
    blob = primitives.aead_encrypt(enc.shared, share.encode(), aad=aad)
    return WrappedShare(
        holder_name=holder.name,
        generation=generation,
        mlkem_ct=enc.mlkem_ct,
        x_eph_pk=enc.x25519_eph_pk,
        aead_blob=blob,
    )


def unwrap_share(holder: Holder, w: WrappedShare) -> shamir.Share:
    """Unwrap a share. Raises if this holder's key does not match the wrapping."""
    key = kem.decapsulate(holder.kem_kp, w.mlkem_ct, w.x_eph_pk)
    aad = f"{w.holder_name}|gen{w.generation}".encode()
    return shamir.Share.decode(primitives.aead_decrypt(key, w.aead_blob, aad=aad))


# ---------------------------------------------------------------------------
# Genesis output — the durable, PUBLIC record of a generation
# ---------------------------------------------------------------------------


@dataclass
class GenerationRecord:
    """Everything that PERSISTS after a genesis / re-root, per holder.

    Crucially this contains no seed, no sk, and no raw shares — only the public
    root key and the KEM-wrapped shares that live with their holders.
    """

    generation: int
    root_pk: bytes  # public SLH-DSA key; safe to publish
    wrapped: Dict[str, WrappedShare]  # holder_name -> its wrapped share
    k: int
    n: int


@dataclass
class GenesisTransient:
    """Material that exists ONLY during the genesis ceremony on the computer.

    `wipe()` models the computer deleting its copy right after genesis.
    """

    seed: Optional[bytes]
    keypair: Optional[sign.SphincsKeypair]
    raw_shares: Optional[List[shamir.Share]]

    def wipe(self) -> None:
        self.seed = None
        self.keypair = None
        self.raw_shares = None

    @property
    def wiped(self) -> bool:
        return self.seed is None and self.keypair is None and self.raw_shares is None


def genesis(
    holders: Dict[str, Holder],
    *,
    k: int = 2,
    generation: int = 0,
) -> tuple[GenerationRecord, GenesisTransient]:
    """Run a genesis (or re-root) ceremony on the computer.

    Returns the durable GenerationRecord plus the transient material that the
    computer is supposed to wipe. The caller wipes the transient to model the
    "computer holds nothing durable" property.
    """
    names = list(holders.keys())
    n = len(names)
    if not 1 < k <= n:
        raise ValueError("require 1 < k <= n")

    # 1. Generate the SLH-DSA root from a fresh 48-byte seed (the root secret).
    seed = primitives.random_bytes(sign.SPX_SEED_BYTES)
    kp = sign.sphincs_keypair_from_seed(seed)

    # 2. Shamir-split the SEED k-of-n. The seed regenerates the whole keypair,
    #    so custody of the seed == custody of the root.
    raw_shares = shamir.split(seed, n=n, k=k)

    # 3. KEM-wrap each share to its holder in transit.
    wrapped: Dict[str, WrappedShare] = {}
    for holder_name, share in zip(names, raw_shares):
        wrapped[holder_name] = wrap_share_to(holders[holder_name], generation, share)

    record = GenerationRecord(
        generation=generation,
        root_pk=kp.pk,
        wrapped=wrapped,
        k=k,
        n=n,
    )
    transient = GenesisTransient(seed=seed, keypair=kp, raw_shares=list(raw_shares))
    return record, transient


# ---------------------------------------------------------------------------
# Transient reconstruction for a rare continuity event
# ---------------------------------------------------------------------------


class ReconstructError(Exception):
    pass


def reconstruct_seed(
    record: GenerationRecord,
    participating: Dict[str, Holder],
) -> bytes:
    """Transiently reconstruct the root seed from the participating holders.

    Each holder unwraps its own share; shares are combined only in memory. Fewer
    than k participants must NOT yield the seed.
    """
    shares: List[shamir.Share] = []
    for name, holder in participating.items():
        if name not in record.wrapped:
            raise ReconstructError(f"no wrapped share for {name}")
        shares.append(unwrap_share(holder, record.wrapped[name]))
    if len(shares) < record.k:
        raise ReconstructError(
            f"below threshold: {len(shares)} < k={record.k}"
        )
    return shamir.combine(shares)


def reconstruct_keypair(
    record: GenerationRecord,
    participating: Dict[str, Holder],
) -> sign.SphincsKeypair:
    seed = reconstruct_seed(record, participating)
    kp = sign.sphincs_keypair_from_seed(seed)
    if kp.pk != record.root_pk:
        raise ReconstructError("reconstructed key does not match the recorded root")
    return kp


def sign_continuity_event(
    record: GenerationRecord,
    participating: Dict[str, Holder],
    message: bytes,
) -> bytes:
    """Reconstruct transiently and SLH-DSA-sign a continuity event, then forget."""
    kp = reconstruct_keypair(record, participating)
    sig = sign.sphincs_sign(kp, message)
    # kp goes out of scope here — nothing durable retained.
    return sig
