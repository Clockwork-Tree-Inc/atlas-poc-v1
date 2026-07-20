"""Generate cross-implementation parity vectors (known-answer tests).

Two phones run Swift (AtlasCore); the Mac runs Python (this core). If their
Atlas-specific glue diverges by one byte — a length prefix, an info label, an
endianness, a canonical-JSON ordering, the SHA-3 used for H() — then A, B and the
verifier silently disagree and nothing tells you why. These vectors pin every
DETERMINISTIC derivation so the Swift port can be proven byte-identical the day
it compiles.

Scope note: standardized primitives (ML-KEM/ML-DSA keygen, X25519 keygen) use
randomness and are validated inside each library; the divergence risk lives in
*our* glue, which is what these vectors target. ML-KEM/ML-DSA interop is a
runtime encapsulate-here/decapsulate-there check on the Mac, not a static vector.

Run:  python -m tools.gen_parity_vectors      (from backend/)
Writes backend/parity/parity_vectors.json and copies it into the Swift test
bundle at ios/AtlasCore/Tests/AtlasCoreTests/Resources/parity_vectors.json.
"""

from __future__ import annotations

import json
import os
import shutil
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from atlas.crypto.primitives import H, aead_decrypt, hkdf, hkdf_combine, sha3_256
from atlas.keys.derivation import derive_session_key_decoupled, ratchet
from atlas.keys.identity import PseudonymTier, _tsk_halves, handle_of, reassemble_system_id
from atlas.keys.tokens import CapabilityToken
from atlas.params import (
    CONTEXT_TUNNEL, LABEL_RATCHET, LABEL_SESSION,
)
from atlas.provenance.capture import CaptureMetadata
from atlas.provenance.ledger import LedgerStub
from atlas.provenance.live_binding import (
    _attribution_core, _session_commit, _witness_seed,
)
from atlas.provenance.pad import pad_check
from atlas.session.presence import _lk_key, _unwrap_key
from atlas.session.recognition import contribution, evolve_tunnel_key, recognition_value
from atlas.realid.recovery_anchor import recovery_selector
from atlas.session.forensic_ledger import (
    DecisionType, ForensicEvent, Outcome, RiskLevel, Signals, _signal_digest,
)


def hx(b: bytes) -> str:
    return b.hex()


def fixed(n: int, fill: int) -> bytes:
    return bytes([fill]) * n


def build() -> dict:
    vectors: dict = {"_about": "Atlas cross-impl parity vectors; see tools/gen_parity_vectors.py"}

    # 1. SHA3-256 (the protocol hash H)
    vectors["sha3_256"] = [
        {"input": hx(b""), "output": hx(sha3_256(b""))},
        {"input": hx(b"atlas"), "output": hx(sha3_256(b"atlas"))},
        {"input": hx(bytes(range(64))), "output": hx(sha3_256(bytes(range(64))))},
    ]

    # 2. hkdf_combine (length-prefixed multi-input HKDF)
    hc = []
    for parts, info, length in [
        ([b"a", b"bc"], b"info1", 32),
        ([b"", b"x", b"yz"], b"atlas/recognition", 32),
        ([fixed(32, 1), fixed(32, 2)], b"atlas/tunnel", 32),
    ]:
        hc.append({"parts": [hx(p) for p in parts], "info": hx(info),
                   "length": length, "output": hx(hkdf_combine(parts, info=info, length=length))})
    vectors["hkdf_combine"] = hc

    # 3. plain HKDF<SHA256>
    vectors["hkdf"] = [
        {"ikm": hx(fixed(32, 7)), "info": hx(b"atlas/tsk/spx"), "length": 48,
         "output": hx(hkdf(ikm=fixed(32, 7), info=b"atlas/tsk/spx", length=48))},
    ]

    # 4. AES-256-GCM with a FIXED nonce (raw cipher agreement)
    gcm = []
    for key, nonce, aad, pt in [
        (fixed(32, 0), fixed(12, 0), b"", b"hello"),
        (fixed(32, 9), bytes(range(12)), b"aad-bytes", b"the quick brown fox"),
    ]:
        ct = AESGCM(key).encrypt(nonce, pt, aad)
        # sanity: round-trips through our decrypt envelope (nonce||ct)
        assert aead_decrypt(key, nonce + ct, aad) == pt
        gcm.append({"key": hx(key), "nonce": hx(nonce), "aad": hx(aad),
                    "plaintext": hx(pt), "ciphertext_and_tag": hx(ct)})
    vectors["aes256gcm_fixed_nonce"] = gcm

    # 5. forward-secret ratchet
    vectors["ratchet"] = [{
        "prev": hx(fixed(32, 3)), "entropy": hx(b"entropy-t"), "beacon": hx(b"beacon-t"),
        "drand_round": hx(fixed(8, 0)),
        "output": hx(ratchet(fixed(32, 3), entropy_t=b"entropy-t", beacon_t=b"beacon-t", drand_round=fixed(8, 0))),
        "label": LABEL_RATCHET.decode(),
    }]

    # 6. session key (decoupled, the default path)
    # CORRECTED §2.3: the physio-timed clean-QRNG draw is `pole_value` (renamed
    # from `local_qrng_draw`); HKDF input order is unchanged for parity.
    sk = derive_session_key_decoupled(
        lk=fixed(32, 0x11), epoch_key=fixed(32, 0x22), pole_value=fixed(32, 0x33),
        prev_key=fixed(32, 0), context_separator=CONTEXT_TUNNEL, drand_round=fixed(8, 1))
    vectors["session_key_decoupled"] = [{
        "lk": hx(fixed(32, 0x11)), "epoch_key": hx(fixed(32, 0x22)),
        "pole_value": hx(fixed(32, 0x33)), "prev_key": hx(fixed(32, 0)),
        "context_separator": hx(CONTEXT_TUNNEL), "drand_round": hx(fixed(8, 1)),
        "label": LABEL_SESSION.decode(), "output": hx(sk.key),
    }]

    # 7. context key derivation
    vectors["context_key"] = [{
        "session_key": hx(sk.key), "context": "tunnel", "output": hx(sk.context_key("tunnel"))
    }]

    # 8. handle_of (identity handle hashing/labeling)
    enc = bytes(range(80))
    vectors["handle_of"] = [{"public_encoded": hx(enc), "output": hx(handle_of(enc))}]

    # 9. recognition value (X25519 DH from session-key-derived ephemerals)
    sk_a, sk_b, beacon = fixed(32, 0xA1), fixed(32, 0xB2), b"beacon-r1"
    a_priv, a_pub = contribution(sk_a, beacon)
    b_priv, b_pub = contribution(sk_b, beacon)
    rec = recognition_value(my_priv=a_priv, their_pub=b_pub.public, my_pub=a_pub.public, beacon=beacon)
    # both directions must match
    assert rec == recognition_value(my_priv=b_priv, their_pub=a_pub.public, my_pub=b_pub.public, beacon=beacon)
    vectors["recognition"] = [{
        "session_key_a": hx(sk_a), "session_key_b": hx(sk_b), "beacon": hx(beacon),
        "a_pub": hx(a_pub.public), "b_pub": hx(b_pub.public), "recognition": hx(rec),
    }]

    # 10. tunnel key evolution
    vectors["tunnel_evolve"] = [{
        "prev": hx(fixed(32, 5)), "recognition": hx(rec),
        "output": hx(evolve_tunnel_key(fixed(32, 5), rec)),
    }]

    # 11. ledger entry hash
    ledger = LedgerStub()
    r0 = ledger.anchor(fixed(32, 0xCC))
    vectors["ledger_entry"] = [{
        "prev": hx(LedgerStub.GENESIS), "content_hash": hx(fixed(32, 0xCC)), "index": 0,
        "entry_hash": hx(r0.entry_hash),
    }]

    # 12. PAD (depth-plane + moiré)
    real_depth = [0.42, 0.61, 0.95, 1.30, 0.55, 0.78, 1.10, 0.33]
    screen_depth = [0.300, 0.301, 0.299, 0.300, 0.302, 0.300, 0.301, 0.299]
    pad_real = pad_check(depth_map=real_depth, moire_score=0.1)
    pad_screen = pad_check(depth_map=screen_depth, moire_score=0.1)
    vectors["pad"] = [
        {"depth_map": real_depth, "moire": 0.1, "passed": pad_real.passed,
         "depth_variance": pad_real.depth_variance, "digest": hx(pad_real.digest())},
        {"depth_map": screen_depth, "moire": 0.1, "passed": pad_screen.passed,
         "depth_variance": pad_screen.depth_variance, "digest": hx(pad_screen.digest())},
    ]

    # 13. capability-token MAC (canonical JSON + HMAC-SHA256)
    import hmac, hashlib
    payload = CapabilityToken(scope="vault", purpose="read", expiry=100.0, nonce="abcd").  \
        _payload()
    mac = hmac.new(fixed(32, 0x44), payload, hashlib.sha256).hexdigest()
    vectors["token_mac"] = [{
        "session_key": hx(fixed(32, 0x44)), "scope": "vault", "purpose": "read",
        "expiry": 100.0, "nonce": "abcd", "canonical_payload": payload.decode(), "mac": mac,
    }]

    # 14. provenance metadata canonical JSON
    meta = CaptureMetadata(camera_intrinsics="f=26mm", motion="still",
                           captured_at="2026-06-27T12:00:00Z", depth_summary="varied")
    vectors["capture_metadata_canonical"] = [{
        "camera_intrinsics": "f=26mm", "motion": "still",
        "captured_at": "2026-06-27T12:00:00Z", "depth_summary": "varied",
        "canonical": meta.canonical().decode(),
        "hash": hx(H(b"atlas/meta-test", meta.canonical())),
    }]

    # 15. split-TSK identity tree (Locked Model §2.1-2.2). Pins the DETERMINISTIC
    # glue — the HKDF halves, System-ID reassembly, System-ID handle, and the
    # per-child / per-pseudonym seed derivations. (The seed -> keypair -> handle
    # step depends on ML-DSA/Ed25519 seed-expansion and is a runtime interop
    # check, like ML-KEM; the risk that these vectors target is OUR KDF glue.)
    tsk_seed = fixed(32, 0x5A)
    id_rows = []
    for rotation in (0, 1):
        uh, sh = _tsk_halves(tsk_seed, rotation=rotation)
        sid = reassemble_system_id(uh, sh)
        sid_handle = H(b"atlas/system-id-handle", sid)
        children = {
            ctx: hx(hkdf(ikm=sid, info=b"atlas/child/" + ctx.encode() + b"/0", length=32))
            for ctx in ("real-id", "anonymous", "authorship", "recovery")
        }
        pseudonyms = {
            f"{tier.value}:{label}": hx(hkdf(
                ikm=sid,
                info=b"atlas/pseudonym/" + tier.value.encode() + b"/" + label.encode(),
                length=32))
            for tier, label in [(PseudonymTier.PUBLIC, "forum"),
                                (PseudonymTier.PRIVATE, "forum"),
                                (PseudonymTier.ANONYMOUS, "whistle")]
        }
        id_rows.append({
            "tsk_seed": hx(tsk_seed), "rotation": rotation,
            "user_half": hx(uh), "server_half": hx(sh),
            "system_id": hx(sid), "system_id_handle": hx(sid_handle),
            "child_seeds": children, "pseudonym_seeds": pseudonyms,
        })
    vectors["identity_tree_split_tsk"] = id_rows

    # 16. presence-gated unwrap chain (Locked Model §2.3, FIX #7 / #15). The
    # dependency chain continuity -> unwrap epoch key -> unlock LK is pinned as
    # (a) the pure-HKDF unwrap/lk key derivations and (b) a full AEAD decrypt
    # round-trip built with a FIXED nonce so the whole wrap->unwrap path is
    # byte-checked (aead_encrypt uses a random nonce, so we fix it here).
    drand_round8 = fixed(8, 0x07)
    enroll_secret = fixed(32, 0x61)
    epoch_key = fixed(32, 0x62)
    lk_secret = fixed(32, 0x63)
    unwrap_k = _unwrap_key(enroll_secret, drand_round8)
    lk_k = _lk_key(epoch_key, drand_round8)
    nonce = fixed(12, 0x00)
    wrapped_epoch = nonce + AESGCM(unwrap_k).encrypt(nonce, epoch_key, b"atlas/epoch-key")
    wrapped_lk = nonce + AESGCM(lk_k).encrypt(nonce, lk_secret, b"atlas/lk")
    # sanity: the module's unwrap/unlock round-trips the fixed-nonce blobs
    from atlas.session.presence import unlock_lk, unwrap_epoch_key
    assert unwrap_epoch_key(wrapped_epoch, presence_secret=enroll_secret, drand_round=drand_round8) == epoch_key
    assert unlock_lk(wrapped_lk, epoch_key=epoch_key, drand_round=drand_round8) == lk_secret
    vectors["presence_unwrap_chain"] = [{
        "drand_round": hx(drand_round8),
        "enrollment_secret": hx(enroll_secret), "epoch_key": hx(epoch_key), "lk": hx(lk_secret),
        "unwrap_key": hx(unwrap_k), "unwrap_key_info": ("atlas/epoch-unwrap|" + drand_round8.hex()),
        "lk_key": hx(lk_k), "lk_key_info": ("atlas/lk-unlock|" + drand_round8.hex()),
        "nonce": hx(nonce), "epoch_key_aad": "atlas/epoch-key", "lk_aad": "atlas/lk",
        "wrapped_epoch_key": hx(wrapped_epoch), "wrapped_lk": hx(wrapped_lk),
    }]

    # 16b. X-Wing hybrid-KEM combiner transcript (§1.3). Pins the EXACT 5-element
    # order [ss_mlkem, ss_x, mlkem_ct, x_eph_pk, recipient_x_pk] so a Swift port
    # that drops the ciphertext (transcript-binding) is caught STATICALLY, before
    # a phone<->Mac tunnel silently fails to open. Fixed inputs (the ML-KEM/X25519
    # shared secrets are randomized in practice; this pins OUR combiner glue).
    from atlas.params import LABEL_XWING
    xw = dict(ss_mlkem=fixed(32, 0xA1), ss_x=fixed(32, 0xB2), mlkem_ct=fixed(1088, 0xC3),
              x_eph_pk=fixed(32, 0xD4), recipient_x_pk=fixed(32, 0xE5))
    xw_out = hkdf_combine([xw["ss_mlkem"], xw["ss_x"], xw["mlkem_ct"], xw["x_eph_pk"],
                           xw["recipient_x_pk"]], info=LABEL_XWING, length=32)
    vectors["xwing_combine"] = [{
        "ss_mlkem": hx(xw["ss_mlkem"]), "ss_x": hx(xw["ss_x"]), "mlkem_ct": hx(xw["mlkem_ct"]),
        "x_eph_pk": hx(xw["x_eph_pk"]), "recipient_x_pk": hx(xw["recipient_x_pk"]),
        "label": LABEL_XWING.decode(), "output": hx(xw_out),
    }]

    # 17. live-provenance binding cores (Priority 1 / T-25b). The witness
    # signature is over these HASHED inputs, so the Swift port MUST match them
    # byte-for-byte or cross-impl verification fails. Pure H() glue.
    lk_lb = fixed(32, 0x71)
    session_key_lb = fixed(32, 0x72)
    content_hash_lb = fixed(32, 0x73)
    handle_lb = fixed(32, 0x74)
    sc = _session_commit(session_key_lb, content_hash_lb)
    vectors["live_provenance_binding"] = [{
        "lk": hx(lk_lb), "session_key": hx(session_key_lb),
        "content_hash": hx(content_hash_lb), "drand_round": hx(drand_round8),
        "authorship_handle": hx(handle_lb),
        "witness_seed": hx(_witness_seed(lk_lb, drand_round8)),
        "session_commit": hx(sc),
        "attribution_core": hx(_attribution_core(content_hash_lb, drand_round8, handle_lb, sc)),
    }]

    # 18. recovery-anchor SELECTOR (real-you/digital-you). recovery_selector(name,
    # password) = H("atlas/recovery-selector", normalized_name, scrypt(password)). The
    # Swift port must reproduce the name normalization + scrypt params + H glue exactly,
    # or a phone and the Mac resolve to different recovery records.
    rsel_name, rsel_pw = "John Q. Smith", "correct horse battery staple"
    vectors["recovery_selector"] = [{
        "legal_name": rsel_name, "password": rsel_pw,
        "scrypt_n": 1 << 14, "scrypt_r": 8, "scrypt_p": 1,
        "output": hx(recovery_selector(rsel_name, rsel_pw)),
    }]

    # 19. forensic-ledger derivations (per-decision audit). signal_digest + event_hash
    # are the cross-language glue; the AEAD seal + Ed25519 sig use randomness (runtime
    # check on the Mac, not a static vector). Pin a TWO-event chain so prev_hash linking
    # is proven identical.
    sig_a = Signals(factors_ok=True, liveness_present=True, known_device=True)
    sig_b = Signals(sudden_liveness_loss=True, recent_failures=3)
    sd_a, sd_b = _signal_digest(sig_a), _signal_digest(sig_b)
    ctx = fixed(16, 0x5A)
    e0 = ForensicEvent(seq=0, prev_hash=b"\x00" * 32, drand_round=drand_round8,
                       decision=DecisionType.LOGIN, outcome=Outcome.ALLOW,
                       risk=RiskLevel.ROUTINE, context_handle=ctx, signal_digest=sd_a)
    e1 = ForensicEvent(seq=1, prev_hash=e0.event_hash(), drand_round=drand_round8,
                       decision=DecisionType.HIGH_STAKES, outcome=Outcome.ESCALATE,
                       risk=RiskLevel.SUSPICIOUS, context_handle=ctx, signal_digest=sd_b)
    vectors["forensic_signal_digest"] = [
        {"signals": "factors_ok,liveness_present,known_device", "output": hx(sd_a)},
        {"signals": "sudden_liveness_loss,recent_failures=3", "output": hx(sd_b)},
    ]
    vectors["forensic_event_chain"] = [
        {"seq": 0, "prev_hash": hx(b"\x00" * 32), "drand_round": hx(drand_round8),
         "decision": "login", "outcome": "allow", "risk": 0,
         "context_handle": hx(ctx), "signal_digest": hx(sd_a), "output": hx(e0.event_hash())},
        {"seq": 1, "prev_hash": hx(e0.event_hash()), "drand_round": hx(drand_round8),
         "decision": "high-stakes", "outcome": "escalate", "risk": 1,
         "context_handle": hx(ctx), "signal_digest": hx(sd_b), "output": hx(e1.event_hash())},
    ]

    # 20. threshold biometric-key seal (TRUST_LAYER.md #1/#2). Pins (a) the new
    # parity-critical `_unlock_key` HKDF derivation and (b) a full cross-impl
    # `unseal`: Python seals here, Swift must reopen it. Shamir + AES-GCM are
    # already parity-covered, so proving unlock_key + an interop unseal proves
    # the whole path. Everything is DETERMINISTIC so regeneration is reproducible:
    # Shamir's coefficient RNG is pinned and the AEAD nonce is fixed.
    from atlas.crypto import shamir as _shamir
    from atlas.recovery import threshold_seal as _ts

    ts_user_half = fixed(32, 0x71)
    ts_context = b"atlas/threshold-seal-parity"
    ts_secret_key = fixed(32, 0x72)          # the custodian secret (fresh CSPRNG in prod)
    ts_plaintext = b"biometric-helper-parity-vector"

    # deterministic 3-of-5 split (pin the coefficient RNG for a reproducible vector)
    _saved_rng = _shamir.random_bytes
    _shamir.random_bytes = lambda n: bytes((0x40 + i) & 0xFF for i in range(n))
    try:
        ts_shares = _shamir.split(ts_secret_key, n=5, k=3)
    finally:
        _shamir.random_bytes = _saved_rng
    assert _shamir.combine(ts_shares[:3]) == ts_secret_key

    ts_unlock = _ts._unlock_key(ts_user_half, ts_secret_key, ts_context)
    ts_nonce = fixed(12, 0x00)               # fixed nonce so the ciphertext is committed
    ts_ct = ts_nonce + AESGCM(ts_unlock).encrypt(ts_nonce, ts_plaintext, ts_context)

    # sanity: the real Swift-mirrored `unseal` reopens this exact artifact
    _sealed = _ts.SealedSketch(ciphertext=ts_ct, storage=_ts.StorageLocation.SELF,
                               policy=_ts.ThresholdPolicy(n=5, m=3), context=ts_context)
    _cshares = [_ts.CustodianShare(_ts.Custodian(f"c{i}"), s) for i, s in enumerate(ts_shares)]
    assert _ts.unseal(_sealed, user_half=ts_user_half, custodian_shares=_cshares[:3]) == ts_plaintext

    vectors["threshold_unlock_key"] = [{
        "user_half": hx(ts_user_half), "custodian_secret": hx(ts_secret_key),
        "context": hx(ts_context), "output": hx(ts_unlock),
    }]
    vectors["threshold_seal"] = [{
        "user_half": hx(ts_user_half), "context": hx(ts_context),
        "plaintext": hx(ts_plaintext), "ciphertext": hx(ts_ct),
        "unlock_key": hx(ts_unlock), "n": 5, "m": 3,
        "shares": [{"index": s.index, "y": hx(s.y)} for s in ts_shares],
    }]

    # 21. individual ledger — Merkle tree + commitment + global anchor (TRUST_LAYER.md #8/#9).
    # All deterministic H() derivations; the Swift mirror must reproduce every byte.
    from atlas.ledger import merkle as _mk
    from atlas.ledger.global_anchor import GlobalAnchorLog as _GAL
    from atlas.ledger.individual import commit as _commit

    lg_leaves = [fixed(32, 0xA0 + i) for i in range(5)]
    lg_root = _mk.merkle_root(lg_leaves)
    lg_proofs = []
    for i in range(len(lg_leaves)):
        path = _mk.inclusion_proof(lg_leaves, i)
        lg_proofs.append({"index": i, "leaf": hx(lg_leaves[i]),
                          "path": [{"sibling": hx(s), "right": r} for s, r in path]})
    vectors["merkle_tree"] = [{
        "leaves": [hx(x) for x in lg_leaves], "root": hx(lg_root),
        "empty_root": hx(_mk.empty_root()), "leaf0_hash": hx(_mk.leaf_hash(lg_leaves[0])),
        "proofs": lg_proofs,
    }]

    lg_content = b"ledger-commit-parity"
    lg_opening = fixed(32, 0x5C)
    lg_commitment, _ = _commit(lg_content, lg_opening)
    vectors["ledger_commit"] = [{
        "content": hx(lg_content), "opening": hx(lg_opening), "commitment": hx(lg_commitment),
    }]

    ga = _GAL()
    ga_owner_a, ga_owner_b = fixed(16, 0xAA), fixed(16, 0xBB)
    ga_r1 = ga.anchor(ga_owner_a, lg_root, fixed(8, 0x07))
    ga_r2 = ga.anchor(ga_owner_b, _mk.empty_root(), fixed(8, 0x08))
    vectors["global_anchor"] = [
        {"prev": hx(_GAL.GENESIS), "owner_id": hx(ga_owner_a), "root": hx(lg_root),
         "drand_round": hx(fixed(8, 0x07)), "index": 0, "entry_hash": hx(ga_r1.entry_hash)},
        {"prev": hx(ga_r1.entry_hash), "owner_id": hx(ga_owner_b), "root": hx(_mk.empty_root()),
         "drand_round": hx(fixed(8, 0x08)), "index": 1, "entry_hash": hx(ga_r2.entry_hash)},
    ]

    # 22. per-space pseudonyms (TRUST_LAYER.md #13) — nym + domain-separated nullifier.
    from atlas.realid.space_pseudonym import space_nullifier as _snull
    from atlas.realid.space_pseudonym import space_nym as _snym

    sp_root, sp_space = fixed(32, 0x9D), b"family"
    vectors["space_pseudonym"] = [{
        "root": hx(sp_root), "space_id": hx(sp_space),
        "nym": hx(_snym(sp_root, sp_space)), "nullifier": hx(_snull(sp_root, sp_space)),
    }]

    # 23. device-attestation contract (TRUST_LAYER.md #11) — capabilities -> tier -> digest.
    from atlas.attestation.device import Capability as _Cap
    from atlas.attestation.device import assurance_tier as _atier
    from atlas.attestation.device import attestation_digest as _adig

    att_dev = fixed(16, 0x11)
    att_cases = []
    for caps in [
        _Cap(0),
        _Cap.LIVENESS,
        _Cap.LIVENESS | _Cap.HIGH_RATE_IMU,
        _Cap.LIVENESS | _Cap.SAME_BODY | _Cap.SECURE_ELEMENT,
        _Cap.LIVENESS | _Cap.HIGH_RATE_IMU | _Cap.SECURE_ELEMENT | _Cap.IDENTITY,
        _Cap.SECURE_ELEMENT | _Cap.IDENTITY,          # fail-closed -> NONE
    ]:
        t = _atier(caps)
        att_cases.append({"capabilities": int(caps), "tier": int(t),
                          "digest": hx(_adig(att_dev, caps, t))})
    vectors["device_attestation"] = [{"device_id": hx(att_dev), "cases": att_cases}]

    # 24. crypto-agility suite id (TRUST_LAYER.md #10) — the committed active-suite commitment.
    from atlas.crypto.agility import CryptoSuite as _CS

    cs_main = _CS(version=1, kem="ml-kem-768+x25519", signature="ml-dsa-65+ed25519", credential="bbs+")
    cs_alt = _CS(version=1, kem="ab", signature="c", credential="d")   # framing check partner
    vectors["crypto_suite"] = [
        {"version": cs_main.version, "kem": cs_main.kem, "signature": cs_main.signature,
         "credential": cs_main.credential, "suite_id": hx(cs_main.suite_id())},
        {"version": cs_alt.version, "kem": cs_alt.kem, "signature": cs_alt.signature,
         "credential": cs_alt.credential, "suite_id": hx(cs_alt.suite_id())},
    ]

    # 25. group-space vault key (TRUST_LAYER.md #12) — tenant-isolated key from the space root.
    from atlas.spaces.space import _vault_key as _svk

    sv_root, sv_space = fixed(32, 0x7E), b"family"
    vectors["space_vault_key"] = [{
        "space_root": hx(sv_root), "space_id": hx(sv_space), "vault_key": hx(_svk(sv_root, sv_space)),
    }]

    # 26. device-attestation signed claim (TRUST_LAYER.md #11) — cross-impl Ed25519 (RFC 8032 is
    # deterministic): Python signs, Swift recomputes the message + verifies the signature.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from atlas.attestation.device import Capability as _AC
    from atlas.attestation.device import claim_message as _acm
    from atlas.attestation.device import sign_capability as _asign

    at_sk = Ed25519PrivateKey.from_private_bytes(fixed(32, 0x33))
    at_pub = at_sk.public_key().public_bytes_raw()
    at_dev, at_cap, at_chal = fixed(16, 0x44), _AC.SECURE_ELEMENT, b"attest-challenge"
    vectors["attestation_claim"] = [{
        "attestor_public": hx(at_pub), "device_id": hx(at_dev), "capability": int(at_cap),
        "challenge": hx(at_chal), "message": hx(_acm(at_dev, at_cap, at_chal)),
        "signature": hx(_asign(at_sk, at_dev, at_cap, at_chal)),
    }]

    # 27. authority — permissioned-grant canonical encoding (grant_id + rights/caveat encode). Pins
    # the parity-critical GLUE (length-prefix framing + domain + field widths + H over the body).
    # Signatures are library-validated at runtime (encapsulate-here/verify-there), not static-vectored;
    # the vector supplies FIXED public-key bytes so grant_id parity is independent of keygen.
    from atlas.crypto.sign import keypair_from_seed as _kfs
    from atlas.authority import Grant, RightSet, Caveat, ROOT
    _gr = _kfs(fixed(32, 0xA1)).public
    _ge = _kfs(fixed(32, 0xB2)).public
    _auth = []
    for level, flags, cavs, depth, parent, epoch in [
        (2, [], [], 0, ROOT, 0),
        (3, ["invite", "pin"], [("expiry", "12345"), ("channel", "general")], 2, fixed(32, 0x07), 9),
    ]:
        g = Grant(grantor=_gr, grantee=_ge, resource=b"res-1",
                  rights=RightSet(level, frozenset(flags)),
                  caveats=frozenset(Caveat(k, v) for k, v in cavs),
                  delegable_depth=depth, parent=parent, epoch=epoch)
        _auth.append({
            "grantor": hx(_gr.encode()), "grantee": hx(_ge.encode()), "resource": hx(b"res-1"),
            "level": level, "flags": sorted(flags),
            "caveats": [{"key": k, "value": v} for k, v in cavs],
            "depth": depth, "parent": hx(parent), "epoch": epoch, "grant_id": hx(g.grant_id()),
        })
    vectors["authority_grant"] = _auth
    vectors["authority_rights_encode"] = [{
        "level": 3, "flags": ["invite", "pin"],
        "output": hx(RightSet(3, frozenset(["invite", "pin"])).encode()),
    }]
    vectors["authority_caveat_encode"] = [{
        "key": "expiry", "value": "12345", "output": hx(Caveat("expiry", "12345").encode()),
    }]

    # 28. forward-secure signer (A13 fix) — the deterministic Merkle GLUE: leaf_hash, node, and
    # root-from-auth-path. Signer keygen + signatures use ML-DSA/Ed25519 (library-validated at
    # runtime, encapsulate-here/verify-there), so they are not static-vectored — only the glue is.
    from atlas.authority.fs_sign import _leaf_hash, _node, _root_from_path
    _lp = [fixed(32, 0x11), fixed(32, 0x22), fixed(32, 0x33), fixed(32, 0x44)]
    _lh = [_leaf_hash(x) for x in _lp]
    _n01, _n23 = _node(_lh[0], _lh[1]), _node(_lh[2], _lh[3])
    _root = _node(_n01, _n23)
    vectors["fs_leaf_hash"] = [{"leaf_public": hx(_lp[0]), "output": hx(_lh[0])}]
    vectors["fs_node"] = [{"left": hx(_lh[0]), "right": hx(_lh[1]), "output": hx(_n01)}]
    vectors["fs_root_from_path"] = [{
        "leaf_hash": hx(_lh[1]), "index": 1, "auth_path": [hx(_lh[0]), hx(_n23)],
        "root": hx(_root_from_path(_lh[1], 1, [_lh[0], _n23])),
    }]

    # 29. market + feed (Phase B #2) — the parity-critical GLUE: the domain-separated, length-prefixed
    # bodies that Receipt / Review / Endorsement sign over, plus the review content-hash. If Swift and
    # Python frame these identically, a review written on one verifies on the other. Signatures are
    # library-validated at runtime (sign-here/verify-there), so only the signed body is static-vectored;
    # fixed public-key bytes make the body parity independent of keygen.
    from atlas.spaces.market import Receipt, Review, Endorsement
    _msel = _kfs(fixed(32, 0xC1)).public
    _mbuy = _kfs(fixed(32, 0xC2)).public
    _mcontent = b"great product"
    _mchash = H(b"atlas/market/review-content", _mcontent)
    _receipt = Receipt(seller=_msel, buyer=_mbuy, item=b"widget-42", epoch=7)
    _review = Review(reviewer=_mbuy, item=b"widget-42", rating=5, content_hash=_mchash, epoch=8)
    _endorse = Endorsement(endorser=_msel, target=b"post-1", epoch=3)
    vectors["market_review_content_hash"] = [{
        "content": hx(_mcontent), "output": hx(_mchash),
    }]
    vectors["market_receipt_body"] = [{
        "seller": hx(_msel.encode()), "buyer": hx(_mbuy.encode()), "item": hx(b"widget-42"),
        "epoch": 7, "output": hx(H(_receipt._body())),
    }]
    vectors["market_review_body"] = [{
        "reviewer": hx(_mbuy.encode()), "item": hx(b"widget-42"), "rating": 5,
        "content_hash": hx(_mchash), "epoch": 8, "output": hx(H(_review._body())),
    }]
    vectors["market_endorse_body"] = [{
        "endorser": hx(_msel.encode()), "target": hx(b"post-1"), "epoch": 3,
        "output": hx(H(_endorse._body())),
    }]

    # 30. polls — poll_id (H over the signed poll body) + the ballot body, pinned over FIXED keys so a
    # poll has the same id on every impl and a ballot verifies cross-impl. Signatures are runtime-
    # validated (sign-here/verify-there); only the signed bodies are static-vectored.
    from atlas.spaces.polls import IdentityTier, Poll, PollResponse
    _pauth = _kfs(fixed(32, 0xD1)).public
    _poll = Poll(author=_pauth, question=b"ship it?", options=(b"yes", b"no", b"maybe"),
                 tier=IdentityTier.VERIFIED_PERSON, epoch=1)
    vectors["poll_id"] = [{
        "author": hx(_pauth.encode()), "question": hx(b"ship it?"),
        "options": [hx(b"yes"), hx(b"no"), hx(b"maybe")], "tier": int(IdentityTier.VERIFIED_PERSON),
        "epoch": 1, "output": hx(_poll.poll_id()),
    }]
    _bk = _kfs(fixed(32, 0xD2)).public
    _presp = PollResponse(poll_id=_poll.poll_id(), choice=2, nullifier=fixed(16, 0xAB),
                          ballot_key=_bk, epoch=7)
    vectors["poll_response_body"] = [{
        "poll_id": hx(_poll.poll_id()), "choice": 2, "nullifier": hx(fixed(16, 0xAB)),
        "ballot_key": hx(_bk.encode()), "epoch": 7, "output": hx(H(_presp._body())),
    }]

    # 31. soul-bound token — token_id (H over the signed body) pinned over FIXED holder/issuer bytes,
    # so an SBT has the same id on every impl and a collected token verifies cross-impl.
    from atlas.participation.soulbound import PARTICIPATION, SoulboundToken
    _sh = _kfs(fixed(32, 0xF1)).public
    _sbt = SoulboundToken(holder=_sh, kind=PARTICIPATION, issuer=_sh, epoch=4, payload=fixed(8, 0xCC))
    vectors["soulbound_token_id"] = [{
        "holder": hx(_sh.encode()), "kind": hx(PARTICIPATION), "issuer": hx(_sh.encode()),
        "epoch": 4, "payload": hx(fixed(8, 0xCC)), "output": hx(_sbt.token_id()),
    }]

    return vectors


def main() -> int:
    vectors = build()
    here = os.path.dirname(__file__)
    backend_out = os.path.abspath(os.path.join(here, "..", "parity", "parity_vectors.json"))
    swift_out = os.path.abspath(os.path.join(
        here, "..", "..", "ios", "AtlasCore", "Tests", "AtlasCoreTests", "Resources", "parity_vectors.json"))
    os.makedirs(os.path.dirname(backend_out), exist_ok=True)
    os.makedirs(os.path.dirname(swift_out), exist_ok=True)
    blob = json.dumps(vectors, indent=2, sort_keys=True)
    with open(backend_out, "w") as f:
        f.write(blob + "\n")
    shutil.copyfile(backend_out, swift_out)
    n = sum(len(v) for k, v in vectors.items() if isinstance(v, list))
    print(f"wrote {n} vectors across {sum(1 for v in vectors.values() if isinstance(v, list))} categories")
    print(f"  backend: {backend_out}")
    print(f"  swift:   {swift_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
