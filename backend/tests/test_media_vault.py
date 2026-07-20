"""Media capture -> sealed vault ingestion (the capture->seal->vault reference).

Every captured item is provenance-signed AND sealed under live presence in one
step, re-verified accountable on open, and fails closed on tamper / no presence /
swapped provenance. Audio has no camera PAD but is accountable all the same.
"""

import os

import pytest

from atlas.beacon import LocalBeacon
from atlas.keys.enclave import SecureEnclave
from atlas.keys.identity import build_identity_tree
from atlas.liveness.bayes import LivenessGate, PoLEState
from atlas.liveness.synthetic import live_stream
from atlas.session.media_vault import MediaKind, MediaVault, ProvenanceRefused
from atlas.session.secure_vault import NotPresent, SecureVault

BIO = b"\xa5" * 64
LK = b"\x11" * 32
SESSION_KEY = b"\x22" * 32
REAL_DEPTH = [0.42, 0.61, 0.95, 1.30, 0.55, 0.78, 1.10, 0.33]   # real 3-D scene


def _live_pole(epoch):
    g = LivenessGate()
    for _, (psl, psnl) in live_stream(40):
        g.update(p_s_given_live=psl, p_s_given_not_live=psnl)
    return g.state(sensor_digest=b"s", drand_round=epoch)


def _dead_pole(epoch):
    return PoLEState(p_live=0.0, state_digest=b"d", drand_round=epoch, operate=False)


def _media_vault():
    tree = build_identity_tree(os.urandom(32))
    author = tree.child("authorship")
    vault = SecureVault(enclave=SecureEnclave(), biometric=BIO, author=author)
    return MediaVault(vault=vault, authorship=author), tree


def _capture(mv, kind, name, content, beacon, **kw):
    return mv.capture(kind=kind, name=name, content=content, live_biometric=BIO,
                      pole=_live_pole(beacon.drand_round()), beacon_round=beacon,
                      lk=LK, session_key=SESSION_KEY, **kw)


def test_photo_capture_seals_and_reopens_accountable():
    mv, _ = _media_vault()
    b = LocalBeacon().round_at(1.0)
    photo = b"\x89PNG\r\n" + b"pixels" * 20
    _capture(mv, MediaKind.PHOTO, "selfie", photo, b, depth_map=REAL_DEPTH, moire_score=0.1)
    content, verdict = mv.open("selfie", live_biometric=BIO, pole=_live_pole(b.drand_round()))
    assert content == photo
    assert verdict.accountable                      # verified-live author + live-LK binding + anchor


def test_video_capture_roundtrip_accountable():
    mv, _ = _media_vault()
    b = LocalBeacon().round_at(1.0)
    clip = b"\x00\x00\x00\x18ftypmp42" + b"frames" * 50
    _capture(mv, MediaKind.VIDEO, "clip", clip, b, depth_map=REAL_DEPTH, moire_score=0.05)
    content, verdict = mv.open("clip", live_biometric=BIO, pole=_live_pole(b.drand_round()))
    assert content == clip and verdict.accountable


def test_audio_capture_has_no_camera_pad_but_is_accountable():
    mv, _ = _media_vault()
    b = LocalBeacon().round_at(1.0)
    voice = b"RIFF" + b"\x00" * 4 + b"WAVEfmt " + b"samples" * 100
    rec = _capture(mv, MediaKind.AUDIO, "memo", voice, b)          # no depth_map passed
    content, verdict = mv.open("memo", live_biometric=BIO, pole=_live_pole(b.drand_round()))
    assert content == voice
    assert verdict.accountable                      # accountable despite no camera PAD
    assert not verdict.pad_advisory.passed          # PAD honestly N/A for audio (no depth)
    assert rec.bundle.metadata.motion == "audio"


def test_media_at_rest_is_unreadable_brick():
    mv, _ = _media_vault()
    b = LocalBeacon().round_at(1.0)
    secret = b"TOP-SECRET-FOOTAGE-PLAINTEXT"
    _capture(mv, MediaKind.PHOTO, "x", secret, b, depth_map=REAL_DEPTH, moire_score=0.1)
    brick = mv.raw_at_rest("x")
    assert secret not in brick and len(brick) > 16


def test_open_without_presence_fails_closed():
    mv, _ = _media_vault()
    b = LocalBeacon().round_at(1.0)
    _capture(mv, MediaKind.PHOTO, "x", b"data-bytes", b, depth_map=REAL_DEPTH, moire_score=0.1)
    with pytest.raises(NotPresent):                 # PoLE not operating -> storage key not released
        mv.open("x", live_biometric=BIO, pole=_dead_pole(b.drand_round()))


def test_capture_without_presence_fails_closed():
    mv, _ = _media_vault()
    b = LocalBeacon().round_at(1.0)
    with pytest.raises(Exception):                  # not verified-live -> refuse to sign/seal
        mv.capture(kind=MediaKind.PHOTO, name="x", content=b"data", live_biometric=BIO,
                   pole=_dead_pole(b.drand_round()), beacon_round=b, lk=LK, session_key=SESSION_KEY,
                   depth_map=REAL_DEPTH, moire_score=0.1)


def test_swapped_provenance_bundle_is_refused():
    """Adversarial: even though each item's bytes stay correctly sealed, an item
    whose provenance bundle is swapped for another capture's must fail closed on
    open — the bundle's content hash no longer matches the sealed content."""
    mv, _ = _media_vault()
    b = LocalBeacon().round_at(1.0)
    _capture(mv, MediaKind.PHOTO, "a", b"AAA-content", b, depth_map=REAL_DEPTH, moire_score=0.1)
    rec_b = _capture(mv, MediaKind.PHOTO, "b", b"BBB-content", b, depth_map=REAL_DEPTH, moire_score=0.1)
    mv._records["a"].bundle = rec_b.bundle          # attacker grafts b's provenance onto a
    with pytest.raises(ProvenanceRefused):
        mv.open("a", live_biometric=BIO, pole=_live_pole(b.drand_round()))


def test_wrong_biometric_cannot_open():
    mv, _ = _media_vault()
    b = LocalBeacon().round_at(1.0)
    _capture(mv, MediaKind.AUDIO, "memo", b"voice-bytes", b)
    with pytest.raises(NotPresent):
        mv.open("memo", live_biometric=b"\x00" * 64, pole=_live_pole(b.drand_round()))
