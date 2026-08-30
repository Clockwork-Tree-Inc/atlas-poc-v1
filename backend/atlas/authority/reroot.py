"""Ledger-anchored re-root — compromise recovery for an authority root (the FUTURE half of A13).

The forward-secure ratchet (`fs_sign`) closes BACKDATING (the past): a stolen current key can't forge
a *past* epoch. It does NOT protect the FUTURE — a thief holding `sk_current` can keep signing the
current/future epochs until the root is replaced. Replacing it is a RE-ROOT: a discrete jump to a
fresh, unrelated forward-secure root.

Two properties make a re-root safe against the very key that was stolen:

  1. AUTHORIZED BY AN INDEPENDENT AUTHORITY — a re-root is signed by a RECOVERY key that is NOT the
     compromised forward-secure signing key (in deployment: the owner's recovery anchor / a guardian
     threshold). So a thief holding only the stolen signing key CANNOT re-root to a key they control.

  2. LEDGER-ANCHORED — the re-root event is appended to the (append-only, tamper-evident) global
     ledger, so its cutover epoch is unforgeable and everyone agrees which root is current and when it
     changed. A thief cannot backdate around it.

After a re-root the old root is RETIRED: `verify_chain` runs against the CURRENT root (the latest
re-rooted `FSPublicKey`), so old-root grants — whose leaves live in the old Merkle tree — simply fail
membership. Live grants are re-issued under the new root. (Honoring old grants that were anchored
BEFORE the cutover, to avoid re-issue, is a documented enhancement; retirement is the safe default.)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from ..crypto.primitives import H
from ..crypto.sign import HybridSigKeypair, HybridSigPublic, sign, verify
from .fs_sign import FSPublicKey

_REROOT_DOMAIN = b"atlas/authority/reroot/v1"


def _lp(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


@dataclass
class ReRoot:
    """A signed, ledger-anchored statement that `resource`'s authority root becomes `new_root`,
    effective at `effective_epoch`. Signed by the RECOVERY authority (independent of the compromised
    forward-secure signing key)."""

    resource: bytes
    new_root: FSPublicKey
    effective_epoch: int
    sig: bytes = b""

    def _body(self) -> bytes:
        return b"".join([
            _REROOT_DOMAIN, _lp(self.resource),
            _lp(self.new_root.root), self.new_root.height.to_bytes(4, "big"),
            self.effective_epoch.to_bytes(8, "big"),
        ])


def make_reroot(recovery_kp: HybridSigKeypair, *, resource: bytes, new_root: FSPublicKey,
                effective_epoch: int) -> ReRoot:
    """Produce a re-root authorized by the recovery authority (the independent key). Anchor the result
    on the ledger; its cutover epoch is then unforgeable."""
    r = ReRoot(resource=resource, new_root=new_root, effective_epoch=effective_epoch)
    r.sig = sign(recovery_kp, r._body())
    return r


def current_root(resource: bytes, *, recovery_public: HybridSigPublic, genesis_root: FSPublicKey,
                 reroots: Sequence[ReRoot]) -> FSPublicKey:
    """The FS root that currently controls `resource`: the latest VALID, recovery-signed re-root (by
    effective epoch), or `genesis_root` if none. A re-root not signed by `recovery_public` is ignored,
    so a thief holding only the compromised signing key cannot move the root."""
    valid = sorted(
        (r for r in reroots
         if r.resource == resource and verify(recovery_public, r._body(), r.sig)),
        key=lambda r: r.effective_epoch,
    )
    return valid[-1].new_root if valid else genesis_root
