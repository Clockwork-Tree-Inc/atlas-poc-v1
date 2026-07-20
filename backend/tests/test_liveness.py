"""Liveness layer (§5, §11 sim)."""

from atlas.liveness.attestation import AttestationSubsystem, RemovalState
from atlas.liveness.bayes import LivenessGate
from atlas.liveness.synthetic import live_stream, spoof_stream


def _run(stream):
    g = LivenessGate()
    for _, (psl, psnl) in stream:
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return g.state(sensor_digest=b"digest", drand_round=b"\x00" * 8)


def test_live_stream_operates():
    st = _run(live_stream(40))
    assert st.operate and st.p_live >= 0.95


def test_spoof_stream_does_not_operate():
    st = _run(spoof_stream(40))
    assert not st.operate


def test_pole_state_has_no_ring_se_sig_but_is_bound():
    st = _run(live_stream(20))
    # PoLE_state digest binds p_live, sensor digest and epoch (§5.2)
    other = _run(live_stream(20))  # same -> same digest (deterministic stream)
    assert st.state_digest == other.state_digest
    assert len(st.state_digest) == 32


def test_attestation_signed_each_step():
    att = AttestationSubsystem()
    st = _run(live_stream(40))
    a = att.attest(st)
    assert a is not None and a.verify() and a.operate
    assert a.drand_round == st.drand_round


def test_attestation_message_is_injective():
    """The signed message must bind exactly one (drand_round, pole_digest, operate,
    challenge). A `|`-delimited concatenation is ambiguous when a field contains
    0x7c (drand_round is raw beacon randomness); length-prefixing makes it injective,
    so a genuine signature cannot be re-parsed into a different drand_round/challenge."""
    from atlas.liveness.attestation import LivenessAttestation as LA
    # sliding the drand_round/pole_digest boundary must NOT collide
    a = LA.message_for(b"\x01\x02|\x04\x05\x06\x07\x08", b"\x11" * 32, True, b"chal")
    b = LA.message_for(b"\x01\x02", b"|\x04\x05\x06\x07\x08" + b"\x11" * 32, True, b"chal")
    assert a != b
    # sliding the challenge boundary must NOT collide either
    c = LA.message_for(b"\x00" * 8, b"\x11" * 32, True, b"AA|BB")
    d = LA.message_for(b"\x00" * 8, b"\x11" * 32, True, b"AA")
    assert c != d


def test_liveness_break_triggers_suspicious_and_wipe():
    att = AttestationSubsystem()
    wiped = {"v": False}
    att.on_wipe(lambda: wiped.__setitem__("v", True))
    spoof = _run(spoof_stream(40))
    assert att.attest(spoof) is None
    assert att.state == RemovalState.SUSPICIOUS
    assert wiped["v"] is True


def test_voluntary_removal_goes_inert_fail_closed():
    """FIX #13: proper/voluntary end is INERT like every other end path — stops
    ratcheting AND fires the wipe. It differs from suspicious only in the benign
    reconnect (light re-bind)."""
    att = AttestationSubsystem()
    wiped = {"v": False}
    att.on_wipe(lambda: wiped.__setitem__("v", True))
    att.remove_voluntary()
    assert att.state == RemovalState.VOLUNTARY
    assert not att.ratchets and not att.contributes_presence   # inert at rest
    assert wiped["v"] is True                                  # key material wiped


def test_all_three_end_paths_are_inert():
    """No end path leaves the device ratcheting or key material live."""
    for trigger in ("voluntary", "suspicious", "liveness_break"):
        att = AttestationSubsystem()
        wiped = {"v": False}
        att.on_wipe(lambda: wiped.__setitem__("v", True))
        if trigger == "voluntary":
            att.remove_voluntary()
        elif trigger == "suspicious":
            att.mark_suspicious()
        else:
            att.attest(_run(spoof_stream(40)))                 # liveness break
        assert not att.ratchets, f"{trigger} still ratchets"
        assert wiped["v"] is True, f"{trigger} did not wipe"


def test_reconnect_discriminator():
    # coherent trajectory after voluntary => light re-bind to active
    att = AttestationSubsystem()
    att.remove_voluntary()
    assert att.reconnect(trajectory_coherent=True) == RemovalState.ACTIVE
    # incoherent => suspicious
    att2 = AttestationSubsystem()
    assert att2.reconnect(trajectory_coherent=False) == RemovalState.SUSPICIOUS
