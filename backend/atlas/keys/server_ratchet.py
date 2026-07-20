"""Server-share proactive ratchet with VERIFIABLE secret sharing (TRUST_LAYER.md, Group E).

Ratchet ONLY the exposed server/HSM share — NEVER the System-ID. The System-ID is the reassembly
of (user half ∧ server share); rotating it would break pseudonym stability, recovery shares, and
selective linkability. Instead we keep the server share's VALUE fixed and rotate only how it is
SHARED across jurisdictions, via presence-gated proactive secret sharing (Herzberg-1995: add a
fresh sharing-of-zero). The reconstructed value — and thus the System-ID — is unchanged; only the
shards' shares move.

VERIFIABLE (Feldman VSS) — this is the hardening the review flagged as missing. The sharing lives
in the prime-order-q subgroup: the dealer publishes **Feldman commitments** `C_j = G^{a_j}` to the
polynomial coefficients (`C_0 = G^secret`), and every share is checkable against them
(`G^share == Π C_j^{index^j}`). So a malicious or buggy shard that presents a corrupted share is
DETECTED (`CheatingShard`) instead of silently shifting the reconstructed secret. Each proactive
refresh multiplies in the zero-sharing's commitments (`C_0` is unchanged because its `Z_0 = G^0 = 1`
— cryptographic proof the secret did not move).

INVARIANTS (unchanged): the refresh is TIMED by the LK/epoch cadence (`epoch_trigger`, QRNG-valued,
presence-gated), never a server clock; the injected VALUE is fresh QRNG. A roving adversary who
holds shares from DIFFERENT epochs cannot combine them — cross-epoch shares fail verification
against the current commitments. Jurisdictional distribution across independent operators is a
PRECONDITION; a single-jurisdiction deployment simulates the topology and delivers none of the
compulsion-resistance.

Server-side infrastructure (HSM + shards): Python reference-of-record, no client/Swift mirror
(same posture as `recovery/oprf.py`). Reuses the 2048-bit safe-prime group from `recovery/oprf`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

from ..recovery.oprf import _P as _P
from ..recovery.oprf import _Q as _Q
from ..recovery.oprf import _random_scalar

# Generator of the order-q subgroup (a QR ⇒ order q), shared with the ZK module.
_G = pow(2, 2, _P)
_SECRET_BYTES = 32


class RatchetError(Exception):
    pass


class CheatingShard(RatchetError):
    """A presented share is inconsistent with the published Feldman commitments — a corrupt or
    malicious shard, or a share from a different epoch. Detected, not silently absorbed."""


def _eval_poly(coeffs: Sequence[int], x: int) -> int:
    """Evaluate Σ coeffs[j]·x^j mod q (Horner)."""
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % _Q
    return acc


def _lagrange_at_zero(points: Sequence[tuple[int, int]]) -> int:
    """Interpolate the polynomial at 0 (the secret) from (x, y) points, over Z_q."""
    secret = 0
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = (num * (-xj)) % _Q
            den = (den * (xi - xj)) % _Q
        secret = (secret + yi * num * pow(den, -1, _Q)) % _Q
    return secret


@dataclass
class JurisdictionShard:
    """One shard: which jurisdiction, its x-coordinate, and its current share (an element of Z_q)."""

    jurisdiction: str
    index: int
    share: int


class ServerShareRatchet:
    """The exposed server share, split k′-of-n′ across jurisdiction shards with Feldman-verifiable
    sharing and proactive refresh — value fixed, sharing rotated, cheating detected."""

    def __init__(self, server_share_secret: bytes, jurisdictions: Sequence[str], k: int) -> None:
        n = len(jurisdictions)
        if not 1 < k <= n:
            raise RatchetError("require 1 < k <= number of jurisdictions")
        if len(server_share_secret) > _SECRET_BYTES:
            raise RatchetError("server share must be <= 32 bytes")
        self._k = k
        secret = int.from_bytes(server_share_secret, "big") % _Q
        coeffs = [secret] + [_random_scalar() for _ in range(k - 1)]
        self.commitments: List[int] = [pow(_G, c, _P) for c in coeffs]   # Feldman C_j = G^{a_j}
        self.shards: List[JurisdictionShard] = [
            JurisdictionShard(j, i + 1, _eval_poly(coeffs, i + 1))
            for i, j in enumerate(jurisdictions)]
        self.epoch = 0

    @property
    def k(self) -> int:
        return self._k

    @property
    def secret_commitment(self) -> int:
        """G^secret — invariant across every refresh (cryptographic proof the value never moved)."""
        return self.commitments[0]

    def verify_share(self, index: int, share: int) -> bool:
        """Feldman check: G^share == Π C_j^{index^j}. Fails for a corrupt share or one from another
        epoch (verified against the CURRENT commitments)."""
        rhs = 1
        for j, cj in enumerate(self.commitments):
            rhs = (rhs * pow(cj, index ** j, _P)) % _P
        return pow(_G, share % _Q, _P) == rhs

    def reconstruct(self, present: Sequence[JurisdictionShard]) -> bytes:
        """Reassemble the server share from ≥ k′ present shards. Every share is Feldman-verified
        first — a cheating shard raises `CheatingShard` rather than corrupting the result."""
        if len(present) < self._k:
            raise RatchetError(f"need {self._k} jurisdictions present, got {len(present)}")
        for sh in present:
            if not self.verify_share(sh.index, sh.share):
                raise CheatingShard(
                    f"shard {sh.jurisdiction!r} presented a share inconsistent with the commitments")
        secret = _lagrange_at_zero([(sh.index, sh.share) for sh in present])
        return secret.to_bytes(_SECRET_BYTES, "big")

    def proactive_refresh(self, *, epoch_trigger: bytes) -> None:
        """Rotate every shard's share by a fresh sharing-of-zero (constant term 0) and update the
        commitments homomorphically. The secret commitment C_0 is unchanged (Z_0 = G^0 = 1), so the
        secret — and the System-ID — provably does not move; only the shares rotate. `epoch_trigger`
        TIMES the step; the injected value is fresh QRNG."""
        if not epoch_trigger:
            raise RatchetError("refresh must be timed by a presence/epoch trigger")
        z_coeffs = [0] + [_random_scalar() for _ in range(self._k - 1)]
        z_commitments = [pow(_G, c, _P) for c in z_coeffs]      # Z_0 = G^0 = 1
        self.shards = [
            JurisdictionShard(sh.jurisdiction, sh.index, (sh.share + _eval_poly(z_coeffs, sh.index)) % _Q)
            for sh in self.shards]
        self.commitments = [(c * z) % _P for c, z in zip(self.commitments, z_commitments)]
        self.epoch += 1
