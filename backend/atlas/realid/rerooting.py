"""System-ID re-rooting and TSK rotation (§5, §5.1).

If a System-ID's unlinkability is ever compromised (e.g. a future BBS break
recovers it), the user constructs a NEW System-ID from the durable TSK and
re-issues children — forward-healing. Strictly user-authority gated: no operator,
court, or system path can re-root anyone (holder-authority, no backdoor; §6).

Honest bound (§5): re-rooting heals FORWARD (new pseudonyms unlinkable again, new
root unlinked to the old) but does NOT retroactively un-link PAST activity an
attacker already correlated under the old System-ID. That past correlation, if
any, never reached the real identity — the System-ID is a blind root.
"""

from __future__ import annotations

from dataclasses import dataclass

from .levels import AssuranceLevel
from ..keys.identity import IdentityTree, build_identity_tree


class RerootError(Exception):
    pass


class OperatorForbidden(RerootError):
    """Re-rooting/rotation is holder-authority only — no operator/system path."""


def reroot_system_id(tree: IdentityTree, *, user_authorized: bool) -> IdentityTree:
    """Forward-heal: derive a fresh System-ID from the durable TSK and re-issue
    children. The TSK (root_handle) is unchanged; only the System-ID and the
    children/pseudonyms rotate, so the new generation is unlinkable from the old.

    `user_authorized` must be True and must originate from the user's own
    authority (unlock / in-person recovery). There is no operator path."""
    if not user_authorized:
        raise OperatorForbidden("re-rooting requires the user's own authority (no operator path)")
    return build_identity_tree(tree.tsk_seed, rotation=tree.rotation + 1)


@dataclass(frozen=True)
class FullRecoveryParams:
    """The complete parameter set for the deepest ceremony (§5.1)."""

    in_person: bool
    live_uncoerced_biometric: bool
    threshold_shares_met: bool
    held_fuzz: bool

    @property
    def complete(self) -> bool:
        return all([self.in_person, self.live_uncoerced_biometric,
                    self.threshold_shares_met, self.held_fuzz])


def rotate_tsk(*, new_tsk_seed: bytes, params: FullRecoveryParams, user_authorized: bool) -> IdentityTree:
    """Rotate even the TSK — the highest-stakes operation. Requires the COMPLETE
    full-recovery parameter set (in-person + live uncoerced biometric + threshold
    shares + held fuzz) AND the user's authority. Cannot occur otherwise."""
    if not user_authorized:
        raise OperatorForbidden("TSK rotation requires the user's own authority (no operator path)")
    if not params.complete:
        raise RerootError("TSK rotation requires the complete full-recovery parameter set")
    return build_identity_tree(new_tsk_seed, rotation=0)
