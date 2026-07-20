"""Content provenance + PAD (§8, §10.2 capstone)."""

import os

import pytest

from atlas.beacon import LocalBeacon
from atlas.crypto.sign import sign as hybrid_sign
from atlas.liveness.attestation import AttestationSubsystem
from atlas.liveness.bayes import LivenessGate
from atlas.liveness.synthetic import live_stream
from atlas.keys.identity import build_identity_tree
from atlas.provenance import (
    LedgerStub, NotLiveError, PADRejected, PublicWitnessRegistry,
    pad_check, sign_capture, verify_provenance, CaptureMetadata,
)


# A real 3-D scene: depth varies across regions. A screen: a near-flat plane.
REAL_DEPTH = [0.42, 0.61, 0.95, 1.30, 0.55, 0.78, 1.10, 0.33]
SCREEN_DEPTH = [0.300, 0.301, 0.299, 0.300, 0.302, 0.300, 0.301, 0.299]


def _live_pole(beacon_round):
    """A live PoLE for the given epoch. sign_capture mints the capture-bound
    attestation from the author's own subsystem + this pole (binding is enforced
    inside sign_capture, so callers cannot transplant a stranger's attestation)."""
    g = LivenessGate()
    for _, (psl, psnl) in live_stream(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return g.state(sensor_digest=b"sensor", drand_round=beacon_round.drand_round())


def _meta():
    return CaptureMetadata(camera_intrinsics="f=26mm,pp=(0.5,0.5)", motion="still",
                           captured_at="2026-06-27T12:00:00Z", depth_summary="varied")


def _sign(registry, **kw):
    """Publish the epoch's LK-witness public half (server side), then sign.

    The Living Key is per-epoch / population-level: everyone live+present in an
    epoch derives the same witness key, and the server publishes its public half
    once per epoch. Tests thread a live session (`lk`, `session_key`) through.
    """
    registry.publish(kw["lk"], kw["beacon_round"].drand_round())
    return sign_capture(**kw)


def test_pad_accepts_real_scene_rejects_screen():
    assert pad_check(depth_map=REAL_DEPTH, moire_score=0.1).passed
    flat = pad_check(depth_map=SCREEN_DEPTH, moire_score=0.1)
    assert not flat.passed and any("flat plane" in r for r in flat.reasons)
    moire = pad_check(depth_map=REAL_DEPTH, moire_score=0.9)
    assert not moire.passed and any("moir" in r for r in moire.reasons)


def test_capstone_sign_and_verify_roundtrip():
    tree = build_identity_tree(os.urandom(32))
    att = AttestationSubsystem()
    beacon = LocalBeacon(period_s=3.0)
    rnd = beacon.round_at(1.0)
    ledger = LedgerStub()
    registry = PublicWitnessRegistry()
    lk, sk = os.urandom(32), os.urandom(32)
    content = b"\x89PNG... earliest frame bytes ..."
    bundle = _sign(
        registry, content=content, depth_map=REAL_DEPTH, moire_score=0.1, metadata=_meta(),
        authorship=tree.child("authorship"),
        attestation_subsystem=att, pole=_live_pole(rnd), beacon_round=rnd, ledger=ledger,
        lk=lk, session_key=sk,
    )
    verdict = verify_provenance(bundle, content=content, ledger=ledger, witness_registry=registry)
    assert verdict.ok
    # bound to the right author and epoch
    assert bundle.authorship_handle == tree.child("authorship").handle
    assert bundle.drand_round == rnd.drand_round()


def test_pad_rejects_screen_replay_at_capture_when_policy_reject():
    """Fraud-filter bonus (opt-in): with pad_policy='reject', PAD refuses to sign
    a screen replay at capture. This is NOT the load-bearing guarantee."""
    tree = build_identity_tree(os.urandom(32))
    att = AttestationSubsystem()
    rnd = LocalBeacon().round_at(1.0)
    with pytest.raises(PADRejected):
        sign_capture(content=b"frame", depth_map=SCREEN_DEPTH, moire_score=0.1,
                     metadata=_meta(), authorship=tree.child("authorship"),
                     attestation_subsystem=att, pole=_live_pole(rnd), beacon_round=rnd,
                     ledger=LedgerStub(), lk=os.urandom(32), session_key=os.urandom(32),
                     pad_policy="reject")


def test_pad_is_advisory_not_load_bearing():
    """Reframe: accountable attribution is the verdict; PAD is advisory. A
    capture that FAILS PAD (advisory) still yields a valid accountable verdict —
    the content is bound to an accountable verified human regardless of whether
    the scene was staged."""
    tree = build_identity_tree(os.urandom(32))
    att = AttestationSubsystem()
    rnd = LocalBeacon().round_at(1.0)
    ledger = LedgerStub()
    registry = PublicWitnessRegistry()
    lk, sk = os.urandom(32), os.urandom(32)
    content = b"possibly-staged frame"
    bundle = _sign(registry, content=content, depth_map=SCREEN_DEPTH, moire_score=0.1,  # PAD will flag
                   metadata=_meta(), authorship=tree.child("authorship"),
                   attestation_subsystem=att, pole=_live_pole(rnd), beacon_round=rnd,
                   ledger=ledger, lk=lk, session_key=sk)  # default advisory -> still signs
    verdict = verify_provenance(bundle, content=content, ledger=ledger, witness_registry=registry)
    assert not bundle.pad.passed              # PAD flagged it...
    assert verdict.accountable and verdict.ok  # ...but accountable attribution holds
    assert any("ADVISORY" in r for r in verdict.reasons)


def test_inherited_verification_and_resolution_under_cause():
    """Wire to the Real-ID machinery: a bundle can carry an inherited L1 proof
    ('a verified real human is behind this', ID hidden); the verdict requires it
    when L1 is requested; and the author is resolvable to the System-ID only
    under cause."""
    from atlas.realid import AtlasVerificationAuthority, AssuranceLevel
    from atlas.provenance import resolve_author_under_cause

    tree = build_identity_tree(os.urandom(32))
    authority = AtlasVerificationAuthority()
    _, cred = authority.verify_and_issue(tree.system_id_handle(), AssuranceLevel.L1)
    att = AttestationSubsystem()
    rnd = LocalBeacon().round_at(1.0)
    ledger = LedgerStub()
    registry = PublicWitnessRegistry()
    lk, sk = os.urandom(32), os.urandom(32)
    content = b"authored frame"
    # the bundle carries an UNLINKABLE BBS+ proof (system-id hidden); sign_capture
    # mints it from the author's own credential, bound to this author/content.
    bundle = _sign(registry, content=content, depth_map=REAL_DEPTH, moire_score=0.1,
                   metadata=_meta(), authorship=tree.child("authorship"),
                   attestation_subsystem=att, pole=_live_pole(rnd), beacon_round=rnd,
                   ledger=ledger, lk=lk, session_key=sk, verification_credential=cred)

    # L1 verification: "a verified real human is behind this", ID NOT revealed
    v = verify_provenance(bundle, content=content, ledger=ledger, witness_registry=registry,
                          authority_bbs_key=authority.bbs_key, required_level=AssuranceLevel.L1)
    assert v.ok and v.verification_inherited_ok
    # requesting L1 without the authority key fails
    assert not verify_provenance(bundle, content=content, ledger=ledger, witness_registry=registry,
                                 required_level=AssuranceLevel.L1).verification_inherited_ok
    # accountability: the bundle's bound proof is unlinkable and does NOT resolve;
    # under cause the holder produces a disclosure proof that resolves to the
    # System-ID.
    assert resolve_author_under_cause(authority.bbs_key, bundle.verification_proof) is None
    disclosure = authority.present(cred, nonce=b"cause-nonce", disclose_system_id=True)
    assert resolve_author_under_cause(authority.bbs_key, disclosure) == tree.system_id_handle()


def test_inherited_proof_transplant_is_rejected():
    """A stranger's valid L1 proof cannot be transplanted onto attacker content.
    The inherited proof is bound (via its BBS+ nonce) to (author, content, epoch);
    a proof minted for the victim's author/content does not match the attacker's
    binding, so the verified-human verdict is denied — accountability cannot be
    laundered onto an unverified author."""
    from atlas.realid import AtlasVerificationAuthority, AssuranceLevel

    authority = AtlasVerificationAuthority()
    rnd = LocalBeacon().round_at(1.0)
    ledger = LedgerStub()
    registry = PublicWitnessRegistry()
    # Same epoch -> same population-level LK; both parties are live+present.
    lk, sk = os.urandom(32), os.urandom(32)

    # VICTIM: a genuinely verified human authors their own bundle (bound proof).
    victim = build_identity_tree(os.urandom(32))
    _, vcred = authority.verify_and_issue(victim.system_id_handle(), AssuranceLevel.L1)
    victim_bundle = _sign(registry, content=b"victim content", depth_map=REAL_DEPTH, moire_score=0.1,
                          metadata=_meta(), authorship=victim.child("authorship"),
                          attestation_subsystem=AttestationSubsystem(), pole=_live_pole(rnd),
                          beacon_round=rnd, ledger=ledger, lk=lk, session_key=sk,
                          verification_credential=vcred)
    stolen_proof = victim_bundle.verification_proof   # a real, valid L1 proof

    # ATTACKER: self-minted authorship (never verified), staples the stolen proof.
    attacker = build_identity_tree(os.urandom(32))
    a_ledger = LedgerStub()
    a_bundle = _sign(registry, content=b"ATTACKER FABRICATION", depth_map=REAL_DEPTH, moire_score=0.1,
                     metadata=_meta(), authorship=attacker.child("authorship"),
                     attestation_subsystem=AttestationSubsystem(), pole=_live_pole(rnd),
                     beacon_round=rnd, ledger=a_ledger, lk=lk, session_key=sk)
    a_bundle.verification_proof = stolen_proof
    a_bundle.signature = hybrid_sign(
        attacker.child("authorship").keypair, a_bundle.transcript())  # re-sign their own bundle

    v = verify_provenance(a_bundle, content=b"ATTACKER FABRICATION", ledger=a_ledger,
                          witness_registry=registry,
                          authority_bbs_key=authority.bbs_key, required_level=AssuranceLevel.L1)
    assert not v.verification_inherited_ok and not v.accountable
    assert any("transplant" in r for r in v.reasons)


def test_liveness_attestation_cannot_be_replayed_across_captures():
    """A genuine attestation from capture A cannot be replayed onto a different
    capture B: the attestation challenge is bound to (author, content, epoch), so
    B's verifier recomputes a different expected challenge and rejects it."""
    tree = build_identity_tree(os.urandom(32))
    att = AttestationSubsystem()
    rnd = LocalBeacon().round_at(1.0)
    ledger = LedgerStub()
    registry = PublicWitnessRegistry()
    lk, sk = os.urandom(32), os.urandom(32)
    bundle_a = _sign(registry, content=b"capture A", depth_map=REAL_DEPTH, moire_score=0.1,
                     metadata=_meta(), authorship=tree.child("authorship"),
                     attestation_subsystem=att, pole=_live_pole(rnd), beacon_round=rnd, ledger=ledger,
                     lk=lk, session_key=sk)
    # Build B with A's attestation stapled in (same author, different content).
    b_ledger = LedgerStub()
    bundle_b = _sign(registry, content=b"capture B", depth_map=REAL_DEPTH, moire_score=0.1,
                     metadata=_meta(), authorship=tree.child("authorship"),
                     attestation_subsystem=AttestationSubsystem(), pole=_live_pole(rnd),
                     beacon_round=rnd, ledger=b_ledger, lk=lk, session_key=sk)
    bundle_b.liveness = bundle_a.liveness                    # replay A's attestation
    bundle_b.signature = hybrid_sign(
        tree.child("authorship").keypair, bundle_b.transcript())
    v = verify_provenance(bundle_b, content=b"capture B", ledger=b_ledger, witness_registry=registry)
    assert not v.liveness_ok and not v.ok


def test_signing_requires_verified_live_author():
    tree = build_identity_tree(os.urandom(32))
    att = AttestationSubsystem()
    rnd = LocalBeacon().round_at(1.0)
    # a non-operating attestation can't be produced; simulate "not live" by
    # marking the subsystem suspicious so attest() returns None, then a hand-made
    # non-operating attestation must be refused.
    from atlas.liveness.bayes import LivenessGate
    from atlas.liveness.synthetic import spoof_stream
    g = LivenessGate()
    for _, (psl, psnl) in spoof_stream(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    spoof_pole = g.state(sensor_digest=b"d", drand_round=rnd.drand_round())
    # attest() detects the break and returns None
    assert att.attest(spoof_pole) is None
    # a live pole from a DIFFERENT epoch -> the minted attestation is bound to the
    # wrong epoch and must fail verification downstream.
    att2 = AttestationSubsystem()
    other = LocalBeacon().round_at(99.0)
    ledger = LedgerStub()
    registry = PublicWitnessRegistry()
    lk, sk = os.urandom(32), os.urandom(32)
    bundle = _sign(registry, content=b"frame", depth_map=REAL_DEPTH, moire_score=0.1,
                   metadata=_meta(), authorship=tree.child("authorship"),
                   attestation_subsystem=att2, pole=_live_pole(other),
                   beacon_round=rnd, ledger=ledger, lk=lk, session_key=sk)
    # liveness attestation epoch != bundle epoch -> verdict.liveness_ok False
    verdict = verify_provenance(bundle, content=b"frame", ledger=ledger, witness_registry=registry)
    assert not verdict.liveness_ok and not verdict.ok


def test_tamper_detection_and_anchor():
    tree = build_identity_tree(os.urandom(32))
    att = AttestationSubsystem()
    rnd = LocalBeacon().round_at(1.0)
    ledger = LedgerStub()
    registry = PublicWitnessRegistry()
    lk, sk = os.urandom(32), os.urandom(32)
    content = b"original frame"
    bundle = _sign(registry, content=content, depth_map=REAL_DEPTH, moire_score=0.1,
                   metadata=_meta(), authorship=tree.child("authorship"),
                   attestation_subsystem=att, pole=_live_pole(rnd), beacon_round=rnd, ledger=ledger,
                   lk=lk, session_key=sk)
    # modified content -> integrity fails
    bad = verify_provenance(bundle, content=b"tampered frame", ledger=ledger, witness_registry=registry)
    assert not bad.integrity_ok and not bad.ok
    # wrong asserted author -> handle fails
    wrong = verify_provenance(bundle, content=content, ledger=ledger, witness_registry=registry,
                              asserted_handle=b"\x00" * 32)
    assert not wrong.handle_ok
    # content hash is anchored and the chain verifies
    assert ledger.contains(bundle.content_hash) and ledger.verify_chain()


def test_signature_tamper_fails():
    tree = build_identity_tree(os.urandom(32))
    att = AttestationSubsystem()
    rnd = LocalBeacon().round_at(1.0)
    ledger = LedgerStub()
    registry = PublicWitnessRegistry()
    lk, sk = os.urandom(32), os.urandom(32)
    content = b"frame"
    bundle = _sign(registry, content=content, depth_map=REAL_DEPTH, moire_score=0.1,
                   metadata=_meta(), authorship=tree.child("authorship"),
                   attestation_subsystem=att, pole=_live_pole(rnd), beacon_round=rnd, ledger=ledger,
                   lk=lk, session_key=sk)
    bundle.signature = bytes(bytearray(bundle.signature[:-1]) + bytes([bundle.signature[-1] ^ 0xFF]))
    assert not verify_provenance(bundle, content=content, ledger=ledger,
                                 witness_registry=registry).signature_ok
