"""Derivation, ratchet, tokens, identity tree, recovery (§2, §7)."""

import os
import random

import pytest

from atlas.crypto.sign import sign as hsign
from atlas.keys import recovery as R
from atlas.keys import tokens as T
from atlas.keys.derivation import (
    KeyDestroyedError,
    derive_session_key_decoupled,
    ratchet,
)
from atlas.keys.identity import build_identity_tree, verify_one_to_one


def _sk(prev=b"\x00" * 32):
    return derive_session_key_decoupled(
        lk=b"L" * 32, epoch_key=b"E" * 32, pole_value=os.urandom(32),
        prev_key=prev, context_separator=b"tunnel", drand_round=b"\x00" * 8,
    )


def test_context_keys_are_purpose_separated():
    sk = _sk()
    assert sk.context_key("storage") != sk.context_key("tunnel") != sk.context_key("recognition")


def test_session_key_destroy_is_containment():
    sk = _sk()
    _ = sk.key
    sk.destroy()
    assert not sk.alive
    with pytest.raises(KeyDestroyedError):
        _ = sk.key


def test_ratchet_one_way_forward_secrecy():
    k0 = os.urandom(32)
    k1 = ratchet(k0, entropy_t=b"e1", beacon_t=b"b1", drand_round=b"\x00" * 8)
    k2 = ratchet(k1, entropy_t=b"e2", beacon_t=b"b2", drand_round=b"\x00" * 8)
    assert k0 != k1 != k2
    # deterministic given the same inputs
    assert k1 == ratchet(k0, entropy_t=b"e1", beacon_t=b"b1", drand_round=b"\x00" * 8)


def test_capability_token_scope_expiry():
    key = os.urandom(32)
    tok = T.issue(key, scope="vault", purpose="read", expiry=100.0)
    assert T.verify(key, tok, now=50.0, scope="vault", purpose="read")
    assert not T.verify(key, tok, now=200.0)              # expired
    assert not T.verify(key, tok, now=50.0, purpose="write")  # wrong purpose
    assert not T.verify(os.urandom(32), tok, now=50.0)   # wrong key


def test_capability_token_single_use_replay_cache():
    """T-02 replay-within-TTL: a valid, unexpired token can be presented twice to
    stateless verify(), but a ReplayCache consumes the nonce on first use and
    rejects every later presentation of the same token."""
    key = os.urandom(32)
    tok = T.issue(key, scope="reward", purpose="claim", expiry=100.0)
    # stateless verify accepts the same token repeatedly within its TTL...
    assert T.verify(key, tok, now=50.0) and T.verify(key, tok, now=50.0)
    # ...the replay cache makes it one-shot.
    cache = T.ReplayCache()
    assert cache.verify_once(key, tok, now=50.0, scope="reward", purpose="claim")
    assert not cache.verify_once(key, tok, now=50.0, scope="reward", purpose="claim")  # replay
    # a forged/expired presentation never consumes a nonce (no cache poisoning)
    cache2 = T.ReplayCache()
    assert not cache2.verify_once(key, tok, now=200.0)        # expired -> rejected
    assert cache2.verify_once(key, tok, now=50.0)             # nonce still fresh
    # a distinct token (distinct nonce) is independent
    tok2 = T.issue(key, scope="reward", purpose="claim", expiry=100.0)
    assert cache.verify_once(key, tok2, now=50.0, scope="reward", purpose="claim")


def test_replay_cache_is_bounded_evicts_expired_nonces():
    """The cache only retains nonces of LIVE tokens; expired ones are evicted, so
    memory tracks live tokens, not the all-time count (no unbounded growth)."""
    key = os.urandom(32)
    cache = T.ReplayCache()
    early = T.issue(key, scope="s", purpose="p", expiry=10.0)
    assert cache.verify_once(key, early, now=5.0)
    assert len(cache._seen) == 1
    # a later presentation (past `early`'s expiry) evicts the dead nonce
    late = T.issue(key, scope="s", purpose="p", expiry=100.0)
    assert cache.verify_once(key, late, now=20.0)
    assert len(cache._seen) == 1 and early.nonce not in cache._seen


def test_token_rejects_non_finite_expiry_and_clock():
    """Fail closed on NaN: `now > nan` is False in IEEE-754, so a NaN expiry must
    not mint a never-expiring token, nor a NaN clock accept an expired token."""
    key = os.urandom(32)
    never = T.issue(key, scope="s", purpose="p", expiry=float("nan"))
    assert not T.verify(key, never, now=1e308)
    finite = T.issue(key, scope="s", purpose="p", expiry=100.0)
    assert not T.verify(key, finite, now=float("nan"))
    assert not T.verify(key, finite, now=float("inf"))


def test_identity_tree_structure_and_reproducibility():
    seed = os.urandom(32)
    tree = build_identity_tree(seed)
    assert set(tree.children) == {"real-id", "anonymous", "authorship", "recovery"}
    # per-context pseudonymity: distinct handles per context (§7.1)
    handles = {c: tree.children[c].handle for c in tree.children}
    assert len(set(handles.values())) == 4
    # forward-derivation is reproducible from the seed
    tree2 = build_identity_tree(seed)
    assert tree2.children["authorship"].handle == tree.children["authorship"].handle
    # root handle is stable and opaque
    assert tree.root_handle == build_identity_tree(seed).root_handle


def test_system_id_reassembled_from_both_tsk_halves_neither_alone():
    """Corrected model (§2.1-2.2): the System-ID is reassembled from BOTH the
    user-held TSK half AND the server-HSM half; neither half alone reassembles
    it, and the server half is non-exportable."""
    from atlas.keys.identity import (
        _tsk_halves, reassemble_system_id, ServerHSM, build_identity_tree)
    seed = os.urandom(32)
    user_half, server_half = _tsk_halves(seed)
    assert user_half != server_half
    full = reassemble_system_id(user_half, server_half)
    # neither half alone reproduces it (pair each with a zero/absent counterpart)
    assert reassemble_system_id(user_half, b"\x00" * 32) != full
    assert reassemble_system_id(b"\x00" * 32, server_half) != full
    # the tree's System-ID equals card-half + HSM-half reassembly
    tree = build_identity_tree(seed)
    hsm = ServerHSM(server_half)
    assert hsm.reassemble_system_id(user_half) == tree._system_id_secret
    # the HSM API surface does not export its half (no accessor/plain attribute).
    # NOTE: true non-exportability is the hardware HSM boundary; Python cannot
    # enforce it, so this asserts the API, not memory protection (hardware-gated).
    assert not hasattr(hsm, "server_half")
    assert "server_half" not in vars(hsm)          # only the name-mangled slot exists
    assert not any(callable(getattr(hsm, n)) and n.endswith("half")
                   for n in dir(hsm))              # no *_half accessor method


def test_card_loss_recovery_reconstructs_user_half_x_of_n():
    """If the Atlas Card is lost, the user half is reconstructed from an x-of-n
    split held ACROSS distributed servers (no single node holds it), then combined
    with the server-HSM half to reassemble the SAME System-ID."""
    from atlas.keys.identity import (
        _tsk_halves, ServerHSM, split_user_half_for_recovery, reconstruct_user_half,
        build_identity_tree)
    seed = os.urandom(32)
    user_half, server_half = _tsk_halves(seed)
    hsm = ServerHSM(server_half)
    shares = split_user_half_for_recovery(user_half, n=5, k=3)   # across 5 servers
    # any k=3 of the distributed shares reconstruct the user half...
    recovered = reconstruct_user_half(shares[:3])
    assert recovered == user_half
    # ...and reassemble the same System-ID as the original tree
    assert hsm.reassemble_system_id(recovered) == build_identity_tree(seed)._system_id_secret
    # fewer than k reveals nothing usable (single share != the half)
    assert shares[0].y != user_half


def test_pseudonym_tiers_are_user_selected_and_unlinkable():
    from atlas.keys.identity import PseudonymTier
    tree = build_identity_tree(os.urandom(32))
    pub = tree.pseudonym("shop", PseudonymTier.PUBLIC)
    prv = tree.pseudonym("shop", PseudonymTier.PRIVATE)
    anon = tree.pseudonym("shop", PseudonymTier.ANONYMOUS)
    # distinct tier (or label) -> distinct, unlinkable handle
    assert len({pub.handle, prv.handle, anon.handle}) == 3
    assert tree.pseudonym("bank", PseudonymTier.PUBLIC).handle != pub.handle
    # reproducible from the same reassembled System-ID
    assert build_identity_tree(tree.tsk_seed).pseudonym("shop", PseudonymTier.PUBLIC).handle == pub.handle


def test_one_to_one_verification():
    tree = build_identity_tree(os.urandom(32))
    child = tree.child("authorship")
    chal = b"continuity-challenge"
    sig = hsign(child.keypair, chal)
    ok = verify_one_to_one(
        asserted_handle=child.handle, revealed_public=child.public,
        challenge=chal, signature=sig, live_biometric_matches=True,
    )
    assert ok.ok
    # wrong handle => rejected, signature path short-circuited
    bad = verify_one_to_one(
        asserted_handle=b"\x00" * 32, revealed_public=child.public,
        challenge=chal, signature=sig, live_biometric_matches=True,
    )
    assert not bad.ok and not bad.matched_handle
    # right handle but biometric mismatch => rejected
    nobio = verify_one_to_one(
        asserted_handle=child.handle, revealed_public=child.public,
        challenge=chal, signature=sig, live_biometric_matches=False,
    )
    assert not nobio.ok


def test_continuity_signed_by_tsk_root():
    from atlas.crypto.sign import sphincs_verify, sphincs_keypair_from_seed
    from atlas.crypto.sign import SPX_SEED_BYTES
    tree = build_identity_tree(os.urandom(32))
    sig = tree.sign_continuity(b"re-enrol")
    kp = sphincs_keypair_from_seed(tree._tsk_secret[:SPX_SEED_BYTES])
    assert sphincs_verify(kp.pk, b"re-enrol", sig)


# -- recovery (§7.2/7.3) — STRATIFIED: Enclave (device-present) vs portable shares (loss) --

from atlas.keys.enclave import SecureEnclave


def _enrol():
    seed = os.urandom(32)
    tree = build_identity_tree(seed)
    bio = os.urandom(256)                       # enrolled biometric template
    device = SecureEnclave()                    # the user's enrolled device
    enr = R.enrol_recovery(tree, bio, device=device, passcode="hunter2")
    return seed, tree, bio, device, enr


def _noisy(template: bytes, frac: float) -> bytes:
    # flip `frac` of the bits — a realistic casual-read difference
    out = bytearray(template)
    nbits = int(len(template) * 8 * frac)
    rng = random.Random(1234)
    for _ in range(nbits):
        i = rng.randrange(len(template))
        out[i] ^= 1 << rng.randrange(8)
    return bytes(out)


def test_device_present_card_path_uses_enclave():
    seed, tree, bio, device, enr = _enrol()
    rec = R.recover_via_card(enr, device=device, card_share=enr.share_card,
                             live_biometric=bio, attested=True, user_authorized=True)
    assert rec.tsk_seed == seed


def test_device_present_in_person_path_uses_enclave():
    seed, tree, bio, device, enr = _enrol()
    rec = R.recover_in_person(enr, device=device, live_biometric=bio,
                              attested=True, user_authorized=True, in_person_trusted_context=True)
    assert rec.tsk_seed == seed


def test_enclave_robust_matching_accepts_a_noisy_read():
    """The Enclave's robust matcher accepts a realistically-noisy live read on the
    device-present card path (where a brittle sketch-based match would fail)."""
    seed, tree, bio, device, enr = _enrol()
    noisy = _noisy(bio, 0.25)                    # 25% of bits differ (casual read)
    rec = R.recover_via_card(enr, device=device, card_share=enr.share_card,
                             live_biometric=noisy, attested=True, user_authorized=True)
    assert rec.tsk_seed == seed


def test_total_loss_path_uses_portable_shares_and_no_enclave():
    """Total-loss recovery on a NEW device: the two PORTABLE shares (card + context),
    no Enclave and no biometric — the in-person recovery person is the anti-spoof."""
    seed, tree, bio, device, enr = _enrol()
    # recover_total_loss takes NO device/Enclave and NO biometric by construction.
    rec = R.recover_total_loss(enr, card_share=enr.share_card, context_share=enr.share_context,
                               attested=True, user_authorized=True, in_person_trusted_context=True)
    assert rec.tsk_seed == seed


def test_total_loss_does_not_depend_on_lost_devices_enclave():
    """The lost device (and its Enclave) is gone; total-loss still succeeds, and
    the Enclave device-present paths fail on a DIFFERENT device."""
    seed, tree, bio, device, enr = _enrol()
    # The original device is lost. A different device's Enclave cannot release
    # the device-bound share (device-bound seal):
    new_device = SecureEnclave()
    new_device.enrol_biometric(bio)             # even with the same biometric
    with pytest.raises(R.RecoveryError):
        R.recover_via_card(enr, device=new_device, card_share=enr.share_card,
                           live_biometric=bio, attested=True, user_authorized=True)
    # But total-loss (the two portable shares) succeeds without any Enclave:
    rec = R.recover_total_loss(enr, card_share=enr.share_card, context_share=enr.share_context,
                               attested=True, user_authorized=True, in_person_trusted_context=True)
    assert rec.tsk_seed == seed


def test_total_loss_requires_in_person_ceremony():
    seed, tree, bio, device, enr = _enrol()
    with pytest.raises(R.RecoveryError):
        R.recover_total_loss(enr, card_share=enr.share_card, context_share=enr.share_context,
                             attested=True, user_authorized=True, in_person_trusted_context=False)


def test_never_store_the_biometric():
    seed, tree, bio, device, enr = _enrol()
    # The Enclave keeps the template sealed; the raw template never appears in any artifact.
    assert bio not in enr.enclave_sealed_bio
    assert bio not in device._sealed_template          # sealed under hardware key
    # And no biometric sketch/helper is stored anywhere (fuzzy retired).
    assert not hasattr(enr, "bio_helper")
    assert not hasattr(enr, "wrapped_share_bio")


def test_attestation_precondition_enforced():
    seed, tree, bio, device, enr = _enrol()
    with pytest.raises(R.AttestationRequired):
        R.recover_via_card(enr, device=device, card_share=enr.share_card, live_biometric=bio, attested=False, user_authorized=True)
    with pytest.raises(R.AttestationRequired):
        R.recover_in_person(enr, device=device, live_biometric=bio, attested=False, user_authorized=True, in_person_trusted_context=True)
    with pytest.raises(R.AttestationRequired):
        R.recover_total_loss(enr, card_share=enr.share_card, context_share=enr.share_context,
                             attested=False, user_authorized=True, in_person_trusted_context=True)


def test_recovery_requires_holder_authority_no_operator_path():
    """Locked principle (Credential PQC Posture §6): recovery is triggered ONLY
    by the holder's own authority — there is no operator/court/system path. A
    call lacking holder authority is rejected BEFORE any attestation/biometric
    work, on every path."""
    seed, tree, bio, device, enr = _enrol()
    with pytest.raises(R.HolderAuthorityRequired):
        R.recover_via_card(enr, device=device, card_share=enr.share_card,
                           live_biometric=bio, attested=True, user_authorized=False)
    with pytest.raises(R.HolderAuthorityRequired):
        R.recover_in_person(enr, device=device, live_biometric=bio,
                            attested=True, user_authorized=False, in_person_trusted_context=True)
    with pytest.raises(R.HolderAuthorityRequired):
        R.recover_total_loss(enr, card_share=enr.share_card, context_share=enr.share_context,
                             attested=True, user_authorized=False, in_person_trusted_context=True)
    # the gate precedes attestation: even with attested=False it is the
    # holder-authority error that surfaces first (no operator can substitute).
    with pytest.raises(R.HolderAuthorityRequired):
        R.recover_via_card(enr, device=device, card_share=enr.share_card,
                           live_biometric=bio, attested=False, user_authorized=False)
    # and the recovery-child selector/gate enforces the same principle.
    with pytest.raises(R.HolderAuthorityRequired):
        R.RecoveryChildGate(enr).attempt(asserted_handle=enr.recovery_child_handle,
                                         passcode="hunter2", attested=True, user_authorized=False)


def test_no_single_factor_reconstructs_tsk():
    seed, tree, bio, device, enr = _enrol()
    # impostor biometric => Enclave release fails (card share alone is not enough)
    with pytest.raises(R.RecoveryError):
        R.recover_via_card(enr, device=device, card_share=enr.share_card,
                           live_biometric=os.urandom(256), attested=True, user_authorized=True)


def test_recovery_child_lockout_survives_gate_reinstantiation():
    """The 3-attempt lockout is persisted in the enrolment record, so an attacker
    cannot reset it by constructing a fresh RecoveryChildGate (which would turn
    the limit into unlimited offline guesses)."""
    seed, tree, bio, device, enr = _enrol()
    for _ in range(3):
        with pytest.raises(R.RecoveryError):
            R.RecoveryChildGate(enr).attempt(asserted_handle=enr.recovery_child_handle,
                                             passcode="nope", attested=True, user_authorized=True)
    # a brand-new gate on the SAME record is already locked out
    assert enr._child_attempts_remaining == 0
    with pytest.raises(R.RecoveryError):
        R.RecoveryChildGate(enr).attempt(asserted_handle=enr.recovery_child_handle,
                                         passcode="hunter2", attested=True, user_authorized=True)


def test_recovery_passcode_is_salted_and_stretched():
    """No bare passcode hash: two enrolments of the SAME passcode have different
    stored hashes (random salt), and the stored value is not the trivial digest."""
    _, _, _, _, e1 = _enrol()
    _, _, _, _, e2 = _enrol()
    assert e1._passcode_salt != e2._passcode_salt
    assert e1._passcode_hash != e2._passcode_hash       # salted: same pw, different hash
    import hashlib
    assert e1._passcode_hash != hashlib.sha256(b"hunter2").digest()  # not an unsalted digest


def test_recovery_child_gate_three_attempts():
    seed, tree, bio, device, enr = _enrol()
    gate = R.RecoveryChildGate(enr)
    sess = gate.attempt(asserted_handle=enr.recovery_child_handle, passcode="hunter2", attested=True, user_authorized=True)
    assert sess.handle == tree.child("recovery").handle
    # exhaust attempts with wrong passcode then lock out
    gate2 = R.RecoveryChildGate(enr)
    for _ in range(3):
        with pytest.raises(R.RecoveryError):
            gate2.attempt(asserted_handle=enr.recovery_child_handle, passcode="nope", attested=True, user_authorized=True)
    with pytest.raises(R.RecoveryError):
        gate2.attempt(asserted_handle=enr.recovery_child_handle, passcode="hunter2", attested=True, user_authorized=True)
