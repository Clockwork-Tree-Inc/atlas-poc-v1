"""Parity-vector regression guard (Python side).

Re-loads parity/parity_vectors.json and asserts the Python core still reproduces
every vector. This catches the case where a refactor changes an output but the
generator wasn't re-run — the committed vectors are the contract both Python and
Swift must satisfy. The Swift side asserts the SAME file in AtlasCoreTests.
"""

import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from atlas.crypto.primitives import H, hkdf, hkdf_combine, sha3_256
from atlas.keys.derivation import derive_session_key_decoupled, ratchet
from atlas.keys.identity import PseudonymTier, _tsk_halves, handle_of, reassemble_system_id
from atlas.keys.tokens import CapabilityToken
from atlas.params import CONTEXT_TUNNEL
from atlas.provenance.capture import CaptureMetadata
from atlas.provenance.ledger import LedgerStub
from atlas.provenance.live_binding import _attribution_core, _session_commit, _witness_seed
from atlas.provenance.pad import pad_check
from atlas.session.presence import _lk_key, _unwrap_key, unlock_lk, unwrap_epoch_key
from atlas.session.recognition import contribution, evolve_tunnel_key, recognition_value

VECTORS_PATH = os.path.join(os.path.dirname(__file__), "..", "parity", "parity_vectors.json")


def _load():
    with open(VECTORS_PATH) as f:
        return json.load(f)


def b(h):
    return bytes.fromhex(h)


def test_vectors_file_exists():
    assert os.path.exists(VECTORS_PATH), "run: python -m tools.gen_parity_vectors"


def test_sha3_vectors():
    for v in _load()["sha3_256"]:
        assert sha3_256(b(v["input"])) == b(v["output"])


def test_hkdf_combine_vectors():
    for v in _load()["hkdf_combine"]:
        out = hkdf_combine([b(p) for p in v["parts"]], info=b(v["info"]), length=v["length"])
        assert out == b(v["output"])


def test_hkdf_vectors():
    for v in _load()["hkdf"]:
        assert hkdf(ikm=b(v["ikm"]), info=b(v["info"]), length=v["length"]) == b(v["output"])


def test_aesgcm_fixed_nonce_vectors():
    for v in _load()["aes256gcm_fixed_nonce"]:
        ct = AESGCM(b(v["key"])).encrypt(b(v["nonce"]), b(v["plaintext"]), b(v["aad"]))
        assert ct == b(v["ciphertext_and_tag"])


def test_ratchet_vectors():
    for v in _load()["ratchet"]:
        out = ratchet(b(v["prev"]), entropy_t=b(v["entropy"]), beacon_t=b(v["beacon"]), drand_round=b(v["drand_round"]))
        assert out == b(v["output"])


def test_session_key_vectors():
    for v in _load()["session_key_decoupled"]:
        sk = derive_session_key_decoupled(
            lk=b(v["lk"]), epoch_key=b(v["epoch_key"]), pole_value=b(v["pole_value"]),
            prev_key=b(v["prev_key"]), context_separator=b(v["context_separator"]), drand_round=b(v["drand_round"]))
        assert sk.key == b(v["output"])


def test_handle_vectors():
    for v in _load()["handle_of"]:
        assert handle_of(b(v["public_encoded"])) == b(v["output"])


def test_recognition_vectors():
    for v in _load()["recognition"]:
        a_priv, a_pub = contribution(b(v["session_key_a"]), b(v["beacon"]))
        b_priv, b_pub = contribution(b(v["session_key_b"]), b(v["beacon"]))
        assert a_pub.public == b(v["a_pub"]) and b_pub.public == b(v["b_pub"])
        rec = recognition_value(my_priv=a_priv, their_pub=b_pub.public, my_pub=a_pub.public, beacon=b(v["beacon"]))
        assert rec == b(v["recognition"])


def test_tunnel_evolve_vectors():
    for v in _load()["tunnel_evolve"]:
        assert evolve_tunnel_key(b(v["prev"]), b(v["recognition"])) == b(v["output"])


def test_ledger_vectors():
    for v in _load()["ledger_entry"]:
        ledger = LedgerStub()
        r = ledger.anchor(b(v["content_hash"]))
        assert r.entry_hash == b(v["entry_hash"]) and r.index == v["index"]


def test_pad_vectors():
    for v in _load()["pad"]:
        r = pad_check(depth_map=v["depth_map"], moire_score=v["moire"])
        assert r.passed == v["passed"]
        assert abs(r.depth_variance - v["depth_variance"]) < 1e-9
        assert r.digest() == b(v["digest"])


def test_token_mac_vectors():
    for v in _load()["token_mac"]:
        payload = CapabilityToken(scope=v["scope"], purpose=v["purpose"], expiry=v["expiry"], nonce=v["nonce"])._payload()
        assert payload.decode() == v["canonical_payload"]
        mac = hmac.new(b(v["session_key"]), payload, hashlib.sha256).hexdigest()
        assert mac == v["mac"]


def test_metadata_canonical_vectors():
    for v in _load()["capture_metadata_canonical"]:
        meta = CaptureMetadata(camera_intrinsics=v["camera_intrinsics"], motion=v["motion"],
                               captured_at=v["captured_at"], depth_summary=v["depth_summary"])
        assert meta.canonical().decode() == v["canonical"]
        assert H(b"atlas/meta-test", meta.canonical()) == b(v["hash"])


def test_identity_tree_split_tsk_vectors():
    _TIER = {"public": PseudonymTier.PUBLIC, "private": PseudonymTier.PRIVATE,
             "anonymous": PseudonymTier.ANONYMOUS}
    for v in _load()["identity_tree_split_tsk"]:
        uh, sh = _tsk_halves(b(v["tsk_seed"]), rotation=v["rotation"])
        assert uh == b(v["user_half"]) and sh == b(v["server_half"])
        sid = reassemble_system_id(uh, sh)
        assert sid == b(v["system_id"])
        assert H(b"atlas/system-id-handle", sid) == b(v["system_id_handle"])
        for ctx, exp in v["child_seeds"].items():
            got = hkdf(ikm=sid, info=b"atlas/child/" + ctx.encode() + b"/0", length=32)
            assert got == b(exp)
        for key, exp in v["pseudonym_seeds"].items():
            tier, label = key.split(":", 1)
            got = hkdf(ikm=sid,
                       info=b"atlas/pseudonym/" + _TIER[tier].value.encode() + b"/" + label.encode(),
                       length=32)
            assert got == b(exp)


def test_presence_unwrap_chain_vectors():
    for v in _load()["presence_unwrap_chain"]:
        eid = b(v["drand_round"])
        assert _unwrap_key(b(v["enrollment_secret"]), eid) == b(v["unwrap_key"])
        assert _lk_key(b(v["epoch_key"]), eid) == b(v["lk_key"])
        # full decrypt round-trip against the committed fixed-nonce blobs
        assert unwrap_epoch_key(b(v["wrapped_epoch_key"]),
                                presence_secret=b(v["enrollment_secret"]), drand_round=eid) == b(v["epoch_key"])
        assert unlock_lk(b(v["wrapped_lk"]), epoch_key=b(v["epoch_key"]), drand_round=eid) == b(v["lk"])


def test_xwing_combine_vectors():
    from atlas.params import LABEL_XWING
    for v in _load()["xwing_combine"]:
        out = hkdf_combine(
            [b(v["ss_mlkem"]), b(v["ss_x"]), b(v["mlkem_ct"]), b(v["x_eph_pk"]), b(v["recipient_x_pk"])],
            info=LABEL_XWING, length=32)
        assert out == b(v["output"])


def test_live_provenance_binding_vectors():
    for v in _load()["live_provenance_binding"]:
        assert _witness_seed(b(v["lk"]), b(v["drand_round"])) == b(v["witness_seed"])
        sc = _session_commit(b(v["session_key"]), b(v["content_hash"]))
        assert sc == b(v["session_commit"])
        core = _attribution_core(b(v["content_hash"]), b(v["drand_round"]), b(v["authorship_handle"]), sc)
        assert core == b(v["attribution_core"])


def test_recovery_selector_vectors():
    from atlas.realid.recovery_anchor import recovery_selector
    for v in _load()["recovery_selector"]:
        assert recovery_selector(v["legal_name"], v["password"]) == b(v["output"])


def test_forensic_signal_digest_vectors():
    # Behavioral pin: the digest is opaque, but the Swift port must reproduce these
    # exact bytes for the same Signals or the chains diverge cross-language.
    outs = {v["output"] for v in _load()["forensic_signal_digest"]}
    from atlas.session.forensic_ledger import Signals, _signal_digest
    got = {
        _signal_digest(Signals(factors_ok=True, liveness_present=True, known_device=True)).hex(),
        _signal_digest(Signals(sudden_liveness_loss=True, recent_failures=3)).hex(),
    }
    assert got == outs


def test_forensic_event_chain_vectors():
    from atlas.session.forensic_ledger import (
        DecisionType, ForensicEvent, Outcome, RiskLevel,
    )
    for v in _load()["forensic_event_chain"]:
        ev = ForensicEvent(
            seq=v["seq"], prev_hash=b(v["prev_hash"]), drand_round=b(v["drand_round"]),
            decision=DecisionType(v["decision"]), outcome=Outcome(v["outcome"]),
            risk=RiskLevel(v["risk"]), context_handle=b(v["context_handle"]),
            signal_digest=b(v["signal_digest"]))
        assert ev.event_hash() == b(v["output"])


def test_authority_grant_vectors():
    """grant_id parity: Python reproduces the committed authority_grant vectors (Swift checks the
    same file in ParityTests.testAuthorityGrant — cross-impl agreement on the grant encoding)."""
    from atlas.authority import RightSet, Caveat, grant_id_from_parts
    for v in _load()["authority_grant"]:
        rights = RightSet(v["level"], frozenset(v["flags"]))
        caveats = frozenset(Caveat(c["key"], c["value"]) for c in v["caveats"])
        gid = grant_id_from_parts(grantor_enc=b(v["grantor"]), grantee_enc=b(v["grantee"]),
                                  resource=b(v["resource"]), rights=rights, caveats=caveats,
                                  depth=v["depth"], parent=b(v["parent"]), epoch=v["epoch"])
        assert gid == b(v["grant_id"])


def test_authority_encode_vectors():
    from atlas.authority import RightSet, Caveat
    for v in _load()["authority_rights_encode"]:
        assert RightSet(v["level"], frozenset(v["flags"])).encode() == b(v["output"])
    for v in _load()["authority_caveat_encode"]:
        assert Caveat(v["key"], v["value"]).encode() == b(v["output"])


def test_fs_merkle_glue_vectors():
    """Forward-secure signer Merkle glue parity (Swift checks the same file in ParityTests)."""
    from atlas.authority.fs_sign import _leaf_hash, _node, _root_from_path
    for v in _load()["fs_leaf_hash"]:
        assert _leaf_hash(b(v["leaf_public"])) == b(v["output"])
    for v in _load()["fs_node"]:
        assert _node(b(v["left"]), b(v["right"])) == b(v["output"])
    for v in _load()["fs_root_from_path"]:
        assert _root_from_path(b(v["leaf_hash"]), v["index"], [b(x) for x in v["auth_path"]]) == b(v["root"])
