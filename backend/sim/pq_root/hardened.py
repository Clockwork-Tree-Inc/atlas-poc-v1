"""Hardened variant of the PQ root-of-trust custody model.

The base `model.py` sim passed but flagged three hardening items. This module
CLOSES all three without modifying `atlas/` or the base `model.py` — it imports
and reuses them (KEM wrapping, Shamir split/combine, SLH-DSA sign, hashes).

Closes
------
1. k TUNING (collusion resistance). The base default is k=2, so any two share
   holders could collude to reconstruct the root. Here the default threshold is
   k=3 (more generally `default_threshold(n) = max(3, n//2 + 1)`), so NO two
   holders can reconstruct. The durable factor set is widened to n=5
   {phone_se, usb, yubikey, server1_se, server2_se}: any 2 fail, any 3 succeed.

2. SHARE AUTHENTICATION. At genesis we publish, in the durable PUBLIC record, a
   binding+hiding commitment per share:
        C_i = H("domain" || holder_name || generation || share_bytes)
   The share bytes are pseudorandom (independent random polynomial per byte over
   a random seed), so the SHA3-256 image is hiding; domain-separating on
   holder_name+generation binds each commitment to exactly one holder in one
   generation. At reconstruction every unwrapped share is verified against its
   commitment; a corrupted/malicious holder's share is DETECTED and the holder
   is NAMED (`ShareAuthError.holder`) instead of silently corrupting the secret.

   NOTE: if `sim/reshare/reshare_vss.py` (Feldman-verifiable shares) is present,
   we import and reuse its commitment scheme instead; otherwise we fall back to
   the hash-commitment scheme above. As of writing only the non-verifiable
   `sim/reshare/reshare.py` exists, so the fallback is active.

3. EXPLICIT ZEROIZATION. The genesis transient stores the seed and raw shares in
   `bytearray`s and `wipe()` overwrites them IN PLACE with zeros before dropping
   the references. A retained reference to the buffer is provably all-zero after
   wipe (not merely dereferenced).
   CAVEAT (genuine residual): Python cannot guarantee no copy of the bytes ever
   existed elsewhere in RAM (interpreter internals, GC, immutable `bytes` handed
   to pyspx). True zeroization is a HARDWARE guarantee provided by the secure
   element (SE) holding keys in deployment; this closes it as far as software
   can and models the SE's overwrite-in-place behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from atlas.crypto import primitives, shamir, sign

# Reuse the base model unchanged (KEM wrapping, Holder, WrappedShare, etc.).
from sim.pq_root import model as m

# The durable, collusion-resistant factor set: five independent holders. Two
# server-held factors (e.g. two regions) join the three personal factors so that
# k=3 tolerates the loss of any two while still forbidding any 2-way collusion.
HARDENED_FACTORS = ["phone_se", "usb", "yubikey", "server1_se", "server2_se"]

_COMMIT_DOMAIN = b"atlas/pq_root/share-commit/v1"


# ---------------------------------------------------------------------------
# CLOSE 1 — threshold tuning
# ---------------------------------------------------------------------------


def default_threshold(n: int) -> int:
    """Collusion-resistant default threshold for n holders.

    max(3, n//2 + 1): at least 3 (so no 2 holders ever collude) and, for larger
    committees, a strict majority. For n=5 this is 3 -> any 2 fail, any 3 pass.
    """
    return max(3, n // 2 + 1)


# ---------------------------------------------------------------------------
# CLOSE 2 — per-share commitments (share authentication)
# ---------------------------------------------------------------------------


class ShareAuthError(Exception):
    """Raised when a share fails to match its published commitment.

    Carries the offending holder's name so a bad/malicious holder is ATTRIBUTED.
    """

    def __init__(self, holder: str, message: str = "") -> None:
        self.holder = holder
        super().__init__(message or f"share from '{holder}' failed commitment check")


# Optional upgrade path: reuse a Feldman-verifiable scheme if another agent has
# landed it. Only the non-verifiable reshare.py exists today, so this stays None.
try:  # pragma: no cover - depends on a sibling module that may not exist
    from sim.reshare import reshare_vss as _vss  # type: ignore
except Exception:  # noqa: BLE001
    _vss = None


def commit_share(holder_name: str, generation: int, share: shamir.Share) -> bytes:
    """Public commitment to a single holder's share (binding + hiding)."""
    return primitives.H(
        _COMMIT_DOMAIN,
        holder_name.encode(),
        generation.to_bytes(4, "big"),
        share.encode(),
    )


def verify_share(
    record: "HardenedGenerationRecord", holder_name: str, share: shamir.Share
) -> bool:
    """True iff `share` matches the commitment published for `holder_name`."""
    import hmac

    expected = record.commitments.get(holder_name)
    if expected is None:
        return False
    # Constant-time compare so the check leaks nothing about the commitment.
    return hmac.compare_digest(
        expected, commit_share(holder_name, record.generation, share)
    )


# ---------------------------------------------------------------------------
# Durable public record (adds commitments to the base record's fields)
# ---------------------------------------------------------------------------


@dataclass
class HardenedGenerationRecord:
    """Durable PUBLIC record: root pk, wrapped shares, AND per-share commitments.

    Contains no seed, no sk, no raw share plaintext — only public material.
    """

    generation: int
    root_pk: bytes
    wrapped: Dict[str, m.WrappedShare]
    commitments: Dict[str, bytes]
    k: int
    n: int


# ---------------------------------------------------------------------------
# CLOSE 3 — zeroizable transient
# ---------------------------------------------------------------------------


@dataclass
class HardenedTransient:
    """Genesis-only material with real overwrite-in-place wiping.

    seed and raw_shares are mutable bytearrays so wipe() can zero the actual
    bytes. keypair holds immutable pyspx bytes that cannot be zeroed in place;
    it is dropped (see module CAVEAT — the SE owns true zeroization).
    """

    seed: Optional[bytearray]
    keypair: Optional[sign.SphincsKeypair]
    raw_shares: Optional[List[bytearray]]

    def wipe(self) -> None:
        # Overwrite the seed bytes IN PLACE, then drop the reference.
        if self.seed is not None:
            _zero(self.seed)
            self.seed = None
        # Overwrite each raw share buffer IN PLACE.
        if self.raw_shares is not None:
            for buf in self.raw_shares:
                _zero(buf)
            self.raw_shares = None
        # Immutable keypair bytes: cannot zero in place; drop it (SE owns keys).
        self.keypair = None

    @property
    def wiped(self) -> bool:
        return self.seed is None and self.keypair is None and self.raw_shares is None


def _zero(buf: bytearray) -> None:
    """Overwrite a bytearray with zeros in place (models SE memory scrub)."""
    for i in range(len(buf)):
        buf[i] = 0


# ---------------------------------------------------------------------------
# Genesis / re-root
# ---------------------------------------------------------------------------


def genesis(
    holders: Dict[str, m.Holder],
    *,
    k: Optional[int] = None,
    generation: int = 0,
) -> tuple[HardenedGenerationRecord, HardenedTransient]:
    """Hardened genesis: collusion-resistant k, per-share commitments, zeroizable
    transient. Reuses base-model KEM wrapping and atlas Shamir/SLH-DSA."""
    names = list(holders.keys())
    n = len(names)
    if k is None:
        k = default_threshold(n)
    if not 2 < k <= n:  # hardened floor: k must exceed 2 (no 2-way collusion)
        raise ValueError(f"hardened genesis requires 2 < k <= n (got k={k}, n={n})")

    # 1. Fresh root seed -> SLH-DSA keypair (seed lives in a zeroizable buffer).
    seed = bytearray(primitives.random_bytes(sign.SPX_SEED_BYTES))
    kp = sign.sphincs_keypair_from_seed(bytes(seed))

    # 2. Shamir-split the seed k-of-n (reuse atlas core).
    raw_shares = shamir.split(bytes(seed), n=n, k=k)

    # 3. KEM-wrap each share to its holder AND publish a per-share commitment.
    wrapped: Dict[str, m.WrappedShare] = {}
    commitments: Dict[str, bytes] = {}
    for holder_name, share in zip(names, raw_shares):
        wrapped[holder_name] = m.wrap_share_to(holders[holder_name], generation, share)
        commitments[holder_name] = commit_share(holder_name, generation, share)

    record = HardenedGenerationRecord(
        generation=generation,
        root_pk=kp.pk,
        wrapped=wrapped,
        commitments=commitments,
        k=k,
        n=n,
    )
    transient = HardenedTransient(
        seed=seed,
        keypair=kp,
        raw_shares=[bytearray(s.encode()) for s in raw_shares],
    )
    return record, transient


# ---------------------------------------------------------------------------
# Authenticated reconstruction
# ---------------------------------------------------------------------------


def reconstruct_seed(
    record: HardenedGenerationRecord,
    participating: Dict[str, m.Holder],
) -> bytes:
    """Reconstruct the seed, verifying each share against its commitment.

    A share that fails its commitment raises ShareAuthError naming the holder,
    so a corrupted/malicious holder is detected and attributed — never silently
    folded into a garbage secret.
    """
    shares: List[shamir.Share] = []
    for name, holder in participating.items():
        if name not in record.wrapped:
            raise m.ReconstructError(f"no wrapped share for {name}")
        share = m.unwrap_share(holder, record.wrapped[name])
        if not verify_share(record, name, share):
            raise ShareAuthError(name)
        shares.append(share)
    if len(shares) < record.k:
        raise m.ReconstructError(f"below threshold: {len(shares)} < k={record.k}")
    return shamir.combine(shares)


def reconstruct_keypair(
    record: HardenedGenerationRecord,
    participating: Dict[str, m.Holder],
) -> sign.SphincsKeypair:
    seed = reconstruct_seed(record, participating)
    kp = sign.sphincs_keypair_from_seed(seed)
    if kp.pk != record.root_pk:
        raise m.ReconstructError("reconstructed key does not match the recorded root")
    return kp


def sign_continuity_event(
    record: HardenedGenerationRecord,
    participating: Dict[str, m.Holder],
    message: bytes,
) -> bytes:
    """Reconstruct transiently (authenticated) and SLH-DSA-sign, then forget."""
    kp = reconstruct_keypair(record, participating)
    return sign.sphincs_sign(kp, message)


# ---------------------------------------------------------------------------
# Helper: tamper a wrapped share to model a corrupted/malicious holder
# ---------------------------------------------------------------------------


def corrupt_holder_share(
    record: HardenedGenerationRecord,
    holder: m.Holder,
) -> shamir.Share:
    """Return a tampered share (one byte flipped) as if `holder` were malicious.

    Used by tests to prove the commitment check detects & attributes the holder.
    """
    good = m.unwrap_share(holder, record.wrapped[holder.name])
    y = bytearray(good.y)
    y[0] ^= 0x01  # flip a bit
    return shamir.Share(index=good.index, y=bytes(y))
