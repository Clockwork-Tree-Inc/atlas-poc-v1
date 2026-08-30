"""Presence interop: one presence attestation -> VC + OIDC + C2PA payload, each offline-verifiable."""
from atlas.attestation.presence_attestation import AssuranceTier, attest
from atlas.crypto.sign import keypair_from_seed
from atlas.interop import oidc, vc
from atlas.interop.presence_interop import as_c2pa_payload, as_oidc, as_vc, presence_assertion


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


BEACON_SIG = b"drand-round-signature-bytes"
BINDING = b"\x11" * 32


def _att(signer, tier=AssuranceTier.WEARABLE, rnd=4242):
    return attest(signer, beacon_round=rnd, beacon_sig=BEACON_SIG, tier=tier, presentation_binding=BINDING)


def test_as_vc_is_a_valid_verifiable_credential():
    signer = kp(1)
    att = _att(signer)
    jws = as_vc(signer, att, subject="persona-01", now=1000.0)
    payload = vc.verify_jws(signer.public, jws)
    assert payload is not None
    cs = payload["vc"]["credentialSubject"]
    assert cs["verified_human"] is True
    assert cs["assurance_tier"] == int(AssuranceTier.WEARABLE)
    assert cs["assurance_tier_name"] == "WEARABLE"
    assert payload["atlas"]["epoch"] == format(4242, "x")


def test_as_oidc_is_a_valid_id_token():
    signer = kp(1)
    att = _att(signer, tier=AssuranceTier.AMBIENT)
    tok = as_oidc(signer, att, subject="persona-01", audience="acme-bank", nonce="n-123", now=1000.0)
    claims = oidc.verify_id_token(signer.public, tok, audience="acme-bank")
    assert claims is not None
    assert claims["atlas_verified_human"] is True
    assert claims["assurance_tier"] == int(AssuranceTier.AMBIENT)
    assert claims["nonce"] == "n-123"


def test_oidc_rejects_wrong_audience():
    signer = kp(1)
    tok = as_oidc(signer, _att(signer), subject="p", audience="acme-bank", nonce="n", now=1000.0)
    assert oidc.verify_id_token(signer.public, tok, audience="someone-else") is None


def test_as_c2pa_payload_carries_the_same_presence_vc():
    signer = kp(1)
    att = _att(signer)
    payload = as_c2pa_payload(signer, att, subject="persona-01", now=1000.0)
    assert payload["verdict"] == "verified-live-human/tier-2"
    assert payload["issuer_did"].startswith("did:atlas:")
    # the embedded VC is a real, offline-verifiable credential (what embed_assertion signs into C2PA)
    inner = vc.verify_jws(signer.public, payload["vc_jws"])
    assert inner is not None and inner["vc"]["credentialSubject"]["verified_human"] is True


def test_forged_issuer_key_does_not_verify():
    signer, attacker = kp(1), kp(9)
    jws = as_vc(signer, _att(signer), subject="p", now=1000.0)
    assert vc.verify_jws(attacker.public, jws) is None      # a different key can't validate the VC


def test_same_attestation_all_three_formats_agree_on_tier_and_round():
    signer = kp(1)
    att = _att(signer, tier=AssuranceTier.WEARABLE, rnd=777)
    a = presence_assertion(signer, att, subject="p", now=1000.0)
    assert a.epoch == format(777, "x")
    assert a.claims["assurance_tier"] == int(AssuranceTier.WEARABLE)
    # VC and OIDC both carry the same tier + epoch
    v = vc.verify_jws(signer.public, as_vc(signer, att, subject="p", now=1000.0))
    o = oidc.verify_id_token(signer.public, as_oidc(signer, att, subject="p", audience="x", nonce="n", now=1000.0), audience="x")
    assert v["vc"]["credentialSubject"]["assurance_tier"] == o["assurance_tier"] == int(AssuranceTier.WEARABLE)
    assert v["atlas"]["epoch"] == o["epoch"] == format(777, "x")
