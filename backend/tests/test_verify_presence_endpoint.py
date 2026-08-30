"""The consumable verified-human endpoint: an app posts a presented VC/OIDC credential, gets a verdict."""
import base64

from atlas.attestation.presence_attestation import AssuranceTier, attest
from atlas.crypto.sign import keypair_from_seed
from atlas.interop.presence_interop import as_oidc, as_vc
from atlas.net.node_server import AtlasNode


def kp(n):
    return keypair_from_seed(bytes([n]) * 32)


def _att(signer, tier=AssuranceTier.WEARABLE, rnd=999):
    return attest(signer, beacon_round=rnd, beacon_sig=b"drand-sig", tier=tier, presentation_binding=b"\x11" * 32)


def _pk(kpair):
    return base64.b64encode(kpair.public.encode()).decode()


def test_verify_presented_vc():
    node = AtlasNode()
    s = kp(1)
    jws = as_vc(s, _att(s), subject="persona-01", now=1000.0)
    r = node.verify_presence(credential_format="vc", token=jws, public_key_b64=_pk(s), min_tier=1)
    assert r["valid"] and r["verified_human"]
    assert r["assurance_tier"] == int(AssuranceTier.WEARABLE)
    assert r["subject"] == "persona-01"
    assert r["epoch"] == format(999, "x")


def test_verify_presented_oidc():
    node = AtlasNode()
    s = kp(1)
    tok = as_oidc(s, _att(s, tier=AssuranceTier.AMBIENT), subject="p", audience="acme", nonce="n", now=1000.0)
    r = node.verify_presence(credential_format="oidc", token=tok, public_key_b64=_pk(s), audience="acme")
    assert r["valid"] and r["verified_human"]
    assert r["assurance_tier"] == int(AssuranceTier.AMBIENT)


def test_min_tier_gate():
    node = AtlasNode()
    s = kp(1)
    jws = as_vc(s, _att(s, tier=AssuranceTier.AMBIENT), subject="p", now=1000.0)
    # ambient credential fails a wearable-minimum requirement
    assert node.verify_presence(credential_format="vc", token=jws, public_key_b64=_pk(s), min_tier=2)["valid"] is False
    assert node.verify_presence(credential_format="vc", token=jws, public_key_b64=_pk(s), min_tier=1)["valid"] is True


def test_wrong_key_rejected():
    node = AtlasNode()
    s, attacker = kp(1), kp(9)
    jws = as_vc(s, _att(s), subject="p", now=1000.0)
    assert node.verify_presence(credential_format="vc", token=jws, public_key_b64=_pk(attacker))["valid"] is False


def test_oidc_wrong_audience_rejected():
    node = AtlasNode()
    s = kp(1)
    tok = as_oidc(s, _att(s), subject="p", audience="acme", nonce="n", now=1000.0)
    assert node.verify_presence(credential_format="oidc", token=tok, public_key_b64=_pk(s), audience="evil")["valid"] is False


def test_provenance_embed_honest_when_c2pa_absent():
    # in this venv c2pa isn't installed; the endpoint must fail HONESTLY, not crash.
    node = AtlasNode()
    r = node.provenance_embed(content_b64=base64.b64encode(b"x").decode(), fmt="application/pdf",
                              vc_jws="jws", issuer_did="did:atlas:x", verdict="v")
    assert r["ok"] is False and "c2pa" in r["error"].lower()


def test_did_register_and_resolve_without_passing_key():
    node = AtlasNode()
    s = kp(1)
    reg = node.did_register(public_key_b64=_pk(s))
    assert reg["ok"] and reg["did_atlas"].startswith("did:atlas:") and reg["did_cid"].startswith("did:cid:f")
    jws = as_vc(s, _att(s), subject="persona-01", now=1000.0)
    r = node.verify_presence(credential_format="vc", token=jws, min_tier=1)   # no public_key
    assert r["valid"] and r["verified_human"] and r["subject"] == "persona-01"


def test_unregistered_presenter_is_unresolved():
    node = AtlasNode()
    s = kp(1)
    jws = as_vc(s, _att(s), subject="p", now=1000.0)
    r = node.verify_presence(credential_format="vc", token=jws)   # not registered + no key
    assert r["valid"] is False and "unresolved" in r["error"]


def test_registered_oidc_resolves_too():
    node = AtlasNode()
    s = kp(1)
    node.did_register(public_key_b64=_pk(s))
    tok = as_oidc(s, _att(s), subject="p", audience="acme", nonce="n", now=1000.0)
    r = node.verify_presence(credential_format="oidc", token=tok, audience="acme")
    assert r["valid"] and r["verified_human"]
