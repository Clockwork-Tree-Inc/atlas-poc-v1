"""WebAuthn mapping (the passkey bridge) — shape + origin binding. Not a full stack."""

import json

from atlas.auth import AuthChallenge
from atlas.auth.webauthn import (
    FLAG_UP,
    FLAG_UV,
    atlas_extension_output,
    authenticator_data,
    b64url,
    challenge_to_client_data,
    client_data_hash,
    signed_over,
    verify_atlas_extension,
)
from atlas.crypto.sign import keypair_from_seed


def test_client_data_maps_relying_party_to_origin():
    ch = AuthChallenge(relying_party="acme-bank", action="login", challenge=b"nonce123")
    cd = json.loads(challenge_to_client_data(ch))
    assert cd["type"] == "webauthn.get"
    assert cd["origin"] == "acme-bank"                     # our relying_party = WebAuthn origin (phishing binding)
    assert cd["challenge"] == b64url(b"nonce123")
    assert "=" not in cd["challenge"]                      # base64url, unpadded


def test_client_data_hash_is_stable_32_bytes():
    h = client_data_hash(b"nonce123", "acme-bank")
    assert len(h) == 32 and h == client_data_hash(b"nonce123", "acme-bank")
    assert h != client_data_hash(b"nonce123", "evil-bank")  # origin changes the hash


def test_authenticator_data_layout_and_flags():
    ad = authenticator_data("acme-bank", user_present=True, user_verified=True, sign_count=5)
    assert len(ad) == 37                                   # rpIdHash(32) + flags(1) + signCount(4)
    assert ad[32] == (FLAG_UP | FLAG_UV)                   # UP + UV set
    assert ad[33:37] == (5).to_bytes(4, "big")             # big-endian sign count
    # UV reflects Atlas's live-presence gate: not verified => bit clear
    assert authenticator_data("acme-bank", user_verified=False)[32] == FLAG_UP
    # signed-over = authenticatorData || clientDataHash
    cdh = client_data_hash(b"nonce123", "acme-bank")
    assert signed_over(ad, cdh) == ad + cdh


def _kp():
    return keypair_from_seed(b"webauthn-ext-test-seed-32-bytes!!")


def test_atlas_extension_verifies_and_binds_challenge_and_origin():
    kp = _kp()
    ch, origin = b"rp-nonce-abc", "https://acme-bank.example"
    out = atlas_extension_output(kp, subject="did:atlas:user-nym", challenge=ch,
                                 origin=origin, epoch="deadbeef", issued_at=1000.0)
    payload = verify_atlas_extension(kp.public, out, challenge=ch, origin=origin)
    assert payload is not None
    assert payload["atlas_verified_human"] is True
    assert payload["challenge"] == b64url(ch) and payload["origin"] == origin


def test_atlas_extension_rejects_wrong_challenge_origin_and_key():
    kp = _kp()
    out = atlas_extension_output(kp, subject="did:atlas:user-nym", challenge=b"rp-nonce-abc",
                                 origin="https://acme-bank.example", epoch="deadbeef", issued_at=1000.0)
    # replayed to a different challenge / origin -> rejected (fail-closed)
    assert verify_atlas_extension(kp.public, out, challenge=b"other-nonce") is None
    assert verify_atlas_extension(kp.public, out, origin="https://evil.example") is None
    # wrong issuer key -> rejected
    other = keypair_from_seed(b"a-totally-different-seed-32bytes!")
    assert verify_atlas_extension(other.public, out) is None


def test_atlas_extension_tamper_breaks_verification():
    kp = _kp()
    out = atlas_extension_output(kp, subject="did:atlas:user-nym", challenge=b"rp-nonce-abc",
                                 origin="https://acme-bank.example", epoch="deadbeef", issued_at=1000.0)
    h, p, s = out.split(".")
    assert verify_atlas_extension(kp.public, h + "." + p + "." + s[:-4] + "AAAA") is None
