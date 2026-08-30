"""Freshness-binding (security review #3): a replayed / pre-canned sample batch — even a
high-entropy, 'varying' one — must NOT read as live. The batch is bound to the CURRENT fresh
beacon round; a stale/mismatched round fail-closes (operate=False) regardless of density.
This is the anti-REPLAY half (is this a fresh, non-replayed device signal). The anti-RANDOM/
synthesis half is MULTI-SENSOR COHERENCE — liveness is coherence across channels, NEVER a PPG
gate; random independent noise is high-entropy but incoherent. Coherence is buildable on the
ambient channels now; HealthyPi only adds MORE coherent channels."""

from atlas.liveness.gbss import EntropyVector, pole_from_gbss


def _live():
    # the same live-looking vectors the density gate accepts (cf. test_gbss)
    return [EntropyVector(s_i=0.8, c_i=0.75, m_i=0.7) for _ in range(30)]


def test_fresh_batch_operates():
    r = b"\x11" * 8
    assert pole_from_gbss(_live(), epoch_round=r, captured_round=r).operate is True


def test_stale_or_replayed_batch_fails_even_when_live_looking():
    r = b"\x11" * 8
    stale = b"\x22" * 8   # captured under a DIFFERENT (old) round -> replay / pre-canned
    assert pole_from_gbss(_live(), epoch_round=r, captured_round=stale).operate is False


def test_legacy_no_binding_is_backward_compatible():
    r = b"\x11" * 8
    # no captured_round -> no freshness claim (legacy callers unaffected)
    assert pole_from_gbss(_live(), epoch_round=r).operate is True
