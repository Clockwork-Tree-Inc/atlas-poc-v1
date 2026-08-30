"""Threshold biometric-key seal — (user-TSK-bound half ∧ m-of-n custodians), with
STORAGE DECOUPLED FROM CONFIDENTIALITY ("ciphertext-anywhere").

This is the trust-layer generalization of the fixed 2-of-2 (biometric ∧ threshold) seal
in `realid/recovery_anchor.py`. Two design commitments (see `TRUST_LAYER.md`, items #1/#2):

  #1  The key that unlocks a user's sealed material is
          user-TSK-bound half   AND   m-of-n custodians.
      Custodians are the user's choice — yourself (1-of-1 is *not* offered: a threshold
      needs m>1), a home node + laptop, a guardianship set, or server shards. The crypto
      is standard Shamir-over-GF(256) (reused from `crypto/shamir`) AND-ed with a
      user-held half through HKDF — exactly the shape of `recovery_anchor._bridge_key`,
      generalized from k fixed to an m-of-n policy and from "biometric" to "user half".

  #2  The sealed output is OPAQUE ciphertext plus a note of WHERE it is stored. Its
      confidentiality does NOT depend on the storage location: whoever holds the
      ciphertext (self, home node, laptop, guardians, or a server shard) learns nothing
      without the user half AND m custodian shares. This is what removes the server-side
      honeypot — the store holds ciphertext under a threshold it cannot alone satisfy.

WHAT THIS MODULE IS NOT:
  * It is not the recovery *tiering* (`TRUST_LAYER.md` #6). WHICH factor supplies the
    `user_half` differs per tier (a real TSK-bound half when device-present; a
    ceremony-derived value at physical-self recovery). This module is where a STORED
    biometric lives on the device-present / social tiers (ciphertext under user-half ∧
    threshold); the total-loss anchor stores no biometric at all (#6).
  * It is not the guardianship model (#4). Custodian *selection* invariants — a private
    set, silent vs witting members, "no all-institutional subset reaches threshold" — live
    in `guardianship`. This module carries the `Custodian.institutional` flag forward so
    #4 can enforce those invariants, but does not itself constrain who the custodians are.

REUSE (do NOT hand-roll): Shamir (`crypto/shamir`), AEAD/HKDF (`crypto/primitives`).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List, Sequence

from ..crypto import shamir
from ..crypto.primitives import aead_decrypt, aead_encrypt, hkdf, random_bytes

# HKDF label for the unlock key. Bound to the seal's context so a share set combined for
# one sealed object cannot open another (domain separation across seals).
_UNLOCK_INFO = b"atlas/threshold-seal/v1"

_KEY_BYTES = 32  # custodian secret + AEAD key width (matches crypto.primitives)


class ThresholdSealError(Exception):
    """Base class for seal/unseal failures — every one is fail-closed (raises)."""


class ThresholdNotMet(ThresholdSealError):
    """Fewer than m custodian shares were presented; the secret cannot be formed."""


class UnsealFailed(ThresholdSealError):
    """AEAD authentication failed — a wrong user half, wrong shares, or tampered
    ciphertext. Which one is deliberately indistinguishable (fail closed, no oracle)."""


class StorageLocation(str, Enum):
    """WHERE a sealed sketch is kept. Advisory metadata only — confidentiality is
    identical for every value (the "ciphertext-anywhere" property, #2)."""

    SELF = "self"                    # the user's own custody (paper/card/device)
    HOME_NODE = "home_node"          # a self-hosted home node
    LAPTOP = "laptop"                # a second personal device
    GUARDIANS = "guardians"          # dispersed among the guardianship set
    SERVER_SHARDED = "server_sharded"  # sharded across server operators/jurisdictions


@dataclass(frozen=True)
class ThresholdPolicy:
    """m-of-n threshold over the custodians. Shamir requires m>1, so a threshold is
    always a genuine quorum — a "store it all yourself" 1-of-1 is a *storage* choice
    (StorageLocation.SELF with the user holding every share), not a m=1 policy."""

    n: int  # total custodians
    m: int  # shares required to reconstruct

    def __post_init__(self) -> None:
        if not 1 < self.m <= self.n < 256:
            raise ValueError("threshold policy requires 1 < m <= n < 256")


@dataclass(frozen=True)
class Custodian:
    """A holder of one share. `label` is an OPAQUE handle — guardianship (#4) keeps the
    real membership private, so nothing here reveals who a custodian is. `institutional`
    marks a custodian as an institution/operator so #4 can enforce "no all-institutional
    subset reaches threshold"; this module records it but does not enforce it."""

    label: str
    institutional: bool = False


@dataclass(frozen=True)
class CustodianShare:
    """One custodian's share of the custodian secret. Distributed to the custodian at
    seal time; m of these (any m) plus the user half reopen the sketch."""

    custodian: Custodian
    share: shamir.Share


@dataclass(frozen=True)
class SealedSketch:
    """Opaque ciphertext + where it is stored (#2). Holding this reveals nothing without
    the user half AND m custodian shares. `context` binds the AEAD (and the unlock key)
    so a sketch cannot be confused for another or moved between users/purposes."""

    ciphertext: bytes
    storage: StorageLocation
    policy: ThresholdPolicy
    context: bytes


def _unlock_key(user_half: bytes, custodian_secret: bytes, context: bytes) -> bytes:
    """The seal key needs BOTH the user-TSK-bound half AND the threshold-combined
    custodian secret — so a wrong/absent user half OR fewer than m custodians cannot form
    it. Deterministic (HKDF): this is the parity-critical derivation every platform must
    reproduce byte-for-byte. Mirrors `recovery_anchor._bridge_key`."""
    return hkdf(ikm=user_half + custodian_secret,
                info=_UNLOCK_INFO + context, length=_KEY_BYTES)


def seal(
    secret: bytes,
    *,
    user_half: bytes,
    custodians: Sequence[Custodian],
    policy: ThresholdPolicy,
    storage: StorageLocation,
    context: bytes = b"",
) -> tuple[SealedSketch, List[CustodianShare]]:
    """Seal `secret` under (user_half ∧ m-of-n custodians). Returns the opaque
    `SealedSketch` (store it anywhere) and one `CustodianShare` per custodian (distribute
    them). `secret` is typically stored biometric enrollment / liveness-baseline material,
    or any material the user wants recoverable under a threshold; `user_half` is the
    user-held, TSK-bound half. The custodian secret is fresh full-entropy CSPRNG — never
    derived from a password — so there is nothing low-entropy to brute-force."""
    # user_half is a full-entropy 32-byte half (TSK-bound or ceremony/OPRF-derived) — NEVER a
    # password. Reject a short/empty one: an empty half silently collapses the seal to
    # custodian-quorum-ONLY (the AND-factor vanishes), and a low-entropy one (e.g. a PIN) is
    # offline-brute-forceable by anyone holding m shares. Fail closed instead of degrading.
    if len(user_half) < _KEY_BYTES:
        raise ValueError(
            f"user_half must be a full-entropy value of >= {_KEY_BYTES} bytes "
            "(TSK-bound / ceremony-derived), not a password/PIN")
    if len(custodians) != policy.n:
        raise ValueError(f"policy expects n={policy.n} custodians, got {len(custodians)}")

    custodian_secret = random_bytes(_KEY_BYTES)
    shares = shamir.split(custodian_secret, n=policy.n, k=policy.m)

    key = _unlock_key(user_half, custodian_secret, context)
    ciphertext = aead_encrypt(key, secret, aad=context)

    sealed = SealedSketch(ciphertext=ciphertext, storage=storage,
                          policy=policy, context=context)
    custodian_shares = [CustodianShare(custodian=c, share=s)
                        for c, s in zip(custodians, shares)]
    return sealed, custodian_shares


def unseal(
    sealed: SealedSketch,
    *,
    user_half: bytes,
    custodian_shares: Sequence[CustodianShare],
) -> bytes:
    """Reopen a `SealedSketch`. Needs the `user_half` AND at least m custodian shares.
    Fail-closed: below threshold raises `ThresholdNotMet`; any wrong factor (bad user
    half, wrong shares, tampered ciphertext) raises `UnsealFailed` with no distinguishing
    oracle. The declared `storage` location is never consulted — confidentiality is
    independent of where the sketch was kept (#2)."""
    if len(custodian_shares) < sealed.policy.m:
        raise ThresholdNotMet(
            f"need {sealed.policy.m} shares, got {len(custodian_shares)}")

    custodian_secret = shamir.combine([cs.share for cs in custodian_shares])
    key = _unlock_key(user_half, custodian_secret, sealed.context)
    try:
        return aead_decrypt(key, sealed.ciphertext, aad=sealed.context)
    except Exception as exc:  # AEAD auth failure = a factor was wrong
        raise UnsealFailed("sketch unseal failed (a factor did not match)") from exc
