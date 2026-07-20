"""WebAuthn mapping (the passkey bridge) — shape + origin binding. Not a full stack."""

import json

from atlas.auth import AuthChallenge
from atlas.auth.webauthn import b64url, challenge_to_client_data, client_data_hash


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
