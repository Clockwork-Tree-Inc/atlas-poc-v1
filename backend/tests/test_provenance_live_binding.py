"""Priority 1 — live-provenance binding (the T-25b fix).

Attribution validity is bound NON-OPTIONALLY to the live provenance of its moment:
a forged credential without the current LK (i.e. without live presence) cannot
produce a valid attribution, and a recipient verifies WITHOUT holding the LK.
"""

import os

import pytest

from atlas.beacon import LocalBeacon
from atlas.crypto.sign import sign as hybrid_sign
from atlas.keys.identity import build_identity_tree
from atlas.liveness.attestation import AttestationSubsystem
from atlas.liveness.bayes import LivenessGate
from atlas.liveness.synthetic import live_stream
from atlas.provenance import (
    LedgerStub, PublicWitnessRegistry, sign_capture, verify_provenance, CaptureMetadata,
)

REAL_DEPTH = [0.42, 0.61, 0.95, 1.30, 0.55, 0.78, 1.10, 0.33]


def _meta():
    return CaptureMetadata("f", "still", "t", "d")


def _live_pole(rnd):
    g = LivenessGate()
    for _, (psl, psnl) in live_stream(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return g.state(sensor_digest=b"s", drand_round=rnd.drand_round())


def _capture(*, lk, session_key, registry, tree=None, content=b"frame", rnd=None, ledger=None,
             authorship_tree=None, publish=True):
    tree = tree or build_identity_tree(os.urandom(32))
    rnd = rnd or LocalBeacon().round_at(1.0)
    ledger = ledger or LedgerStub()
    if publish:
        registry.publish(lk, rnd.drand_round())          # server publishes the epoch witness pub
    bundle = sign_capture(
        content=content, depth_map=REAL_DEPTH, moire_score=0.1, metadata=_meta(),
        authorship=tree.child("authorship"), attestation_subsystem=AttestationSubsystem(),
        pole=_live_pole(rnd), beacon_round=rnd, ledger=ledger, lk=lk, session_key=session_key)
    return tree, ledger, rnd, bundle


def test_forged_bbs_without_lk_is_rejected():
    """A forged/valid credential with NO current LK cannot produce a valid
    attribution: the witness signature (made with the wrong LK) fails against the
    authoritative public registry."""
    registry = PublicWitnessRegistry()
    real_lk, sk = os.urandom(32), os.urandom(32)
    tree, ledger, rnd, good = _capture(lk=real_lk, session_key=sk, registry=registry)
    assert verify_provenance(good, content=b"frame", ledger=ledger, witness_registry=registry).accountable

    # attacker does NOT have the current LK -> signs with a guessed/fake LK
    atk = build_identity_tree(os.urandom(32))
    a_ledger = LedgerStub()
    fake_lk = os.urandom(32)
    a_bundle = sign_capture(
        content=b"FAKE", depth_map=REAL_DEPTH, moire_score=0.1, metadata=_meta(),
        authorship=atk.child("authorship"), attestation_subsystem=AttestationSubsystem(),
        pole=_live_pole(rnd), beacon_round=rnd, ledger=a_ledger, lk=fake_lk, session_key=os.urandom(32))
    v = verify_provenance(a_bundle, content=b"FAKE", ledger=a_ledger, witness_registry=registry)
    assert not v.live_provenance_ok and not v.accountable
    assert any("live-provenance" in r for r in v.reasons)


def test_attribution_requires_live_session():
    """An attribution with no live-provenance binding — even validly authored and
    signed — is not accountable."""
    registry = PublicWitnessRegistry()
    lk, sk = os.urandom(32), os.urandom(32)
    tree, ledger, rnd, good = _capture(lk=lk, session_key=sk, registry=registry)
    # strip the live binding and re-sign as the true author -> still rejected
    good.live_binding = None
    good.signature = hybrid_sign(tree.child("authorship").keypair, good.transcript())
    v = verify_provenance(good, content=b"frame", ledger=ledger, witness_registry=registry)
    assert not v.live_provenance_ok and not v.accountable


def test_impersonation_produces_mismatch():
    """A live participant CAN attribute their own content, but forging an
    attribution that CLAIMS another author is a detectable mismatch (the bundle's
    key hashes to the producer, not the claimed victim). Self-incrimination."""
    registry = PublicWitnessRegistry()
    lk, sk = os.urandom(32), os.urandom(32)
    victim = build_identity_tree(os.urandom(32))
    attacker = build_identity_tree(os.urandom(32))
    _, a_ledger, rnd, bundle = _capture(lk=lk, session_key=sk, registry=registry, tree=attacker,
                                        content=b"c")
    # attacker relabels the bundle to CLAIM the victim as author
    victim_handle = victim.child("authorship").handle
    bundle.authorship_handle = victim_handle
    v = verify_provenance(bundle, content=b"c", ledger=a_ledger, witness_registry=registry,
                          asserted_handle=victim_handle)
    assert not v.handle_ok and not v.accountable       # producer key != claimed victim


def test_backdated_attribution_rejected():
    """The 'when' cannot be moved: a binding made at epoch A cannot be re-presented
    as an earlier epoch B — the witness signature verifies only against A's LK-
    derived public key."""
    registry = PublicWitnessRegistry()
    lk_a, lk_b, sk = os.urandom(32), os.urandom(32), os.urandom(32)
    beacon = LocalBeacon()
    rnd_a, rnd_b = beacon.round_at(9.0), beacon.round_at(1.0)   # B is earlier
    registry.publish(lk_b, rnd_b.drand_round())                    # both epochs published
    tree, ledger, _, bundle = _capture(lk=lk_a, session_key=sk, registry=registry, rnd=rnd_a)
    # attacker backdates: claim the earlier epoch B
    bundle.drand_round = rnd_b.drand_round()
    bundle.signature = hybrid_sign(tree.child("authorship").keypair, bundle.transcript())
    v = verify_provenance(bundle, content=b"frame", ledger=ledger, witness_registry=registry)
    assert not v.live_provenance_ok and not v.accountable


def test_recipient_can_verify_without_lk():
    """1.1 didn't break recipient verifiability: a recipient holding ONLY the
    public witness registry (no LK, no session key) can verify the binding."""
    registry = PublicWitnessRegistry()
    lk, sk = os.urandom(32), os.urandom(32)
    tree, ledger, rnd, good = _capture(lk=lk, session_key=sk, registry=registry)
    # the verifier is given only the PUBLIC registry — lk/session_key appear nowhere
    v = verify_provenance(good, content=b"frame", ledger=ledger, witness_registry=registry)
    assert v.live_provenance_ok and v.accountable
    pub = registry.witness_pub(rnd.drand_round())
    assert pub is not None and lk not in pub.encode()   # registry holds only public material
