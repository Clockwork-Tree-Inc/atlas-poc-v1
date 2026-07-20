import XCTest
import CryptoKit
@testable import AtlasCore

/// Cross-implementation parity: the Swift core must reproduce every vector the
/// Python core generated (backend/tools/gen_parity_vectors.py). This is the
/// proof that two iPhones (Swift) and the Mac verifier (Python) agree on the
/// Atlas-specific glue — run it the moment AtlasCore compiles on the Mac.
///
/// If a vector category fails, the byte where Swift and Python disagree is in
/// that derivation (a length prefix, an info label, endianness, canonical JSON,
/// or the SHA-3 used for H()).
final class ParityTests: XCTestCase {

    private func vectors() throws -> [String: Any] {
        guard let url = Bundle.module.url(forResource: "parity_vectors", withExtension: "json") else {
            throw XCTSkip("parity_vectors.json not bundled; run gen_parity_vectors.py")
        }
        let data = try Data(contentsOf: url)
        return try JSONSerialization.jsonObject(with: data) as! [String: Any]
    }
    private func arr(_ v: [String: Any], _ key: String) -> [[String: Any]] {
        (v[key] as? [[String: Any]]) ?? []
    }
    private func hex(_ s: String) -> Data { Data(hex: s) }

    func testSHA3() throws {
        for v in arr(try vectors(), "sha3_256") {
            XCTAssertEqual(SHA3.sha3_256(hex(v["input"] as! String)), hex(v["output"] as! String))
        }
    }

    func testHKDFCombine() throws {
        for v in arr(try vectors(), "hkdf_combine") {
            let parts = (v["parts"] as! [String]).map { hex($0) }
            let out = Primitives.hkdfCombine(parts, info: hex(v["info"] as! String), length: v["length"] as! Int)
            XCTAssertEqual(out, hex(v["output"] as! String))
        }
    }

    func testHKDF() throws {
        for v in arr(try vectors(), "hkdf") {
            XCTAssertEqual(Primitives.hkdf(ikm: hex(v["ikm"] as! String), info: hex(v["info"] as! String),
                                           length: v["length"] as! Int), hex(v["output"] as! String))
        }
    }

    func testAESGCMFixedNonce() throws {
        for v in arr(try vectors(), "aes256gcm_fixed_nonce") {
            let key = SymmetricKey(data: hex(v["key"] as! String))
            let nonce = try AES.GCM.Nonce(data: hex(v["nonce"] as! String))
            let sealed = try AES.GCM.seal(hex(v["plaintext"] as! String), using: key,
                                          nonce: nonce, authenticating: hex(v["aad"] as! String))
            XCTAssertEqual(sealed.ciphertext + sealed.tag, hex(v["ciphertext_and_tag"] as! String))
        }
    }

    func testRatchet() throws {
        for v in arr(try vectors(), "ratchet") {
            let out = Derivation.ratchet(hex(v["prev"] as! String), entropyT: hex(v["entropy"] as! String),
                                         beaconT: hex(v["beacon"] as! String), drandRound: hex(v["drand_round"] as! String))
            XCTAssertEqual(out, hex(v["output"] as! String))
        }
    }

    func testSessionKey() throws {
        for v in arr(try vectors(), "session_key_decoupled") {
            let sk = Derivation.sessionKeyDecoupled(
                lk: hex(v["lk"] as! String), epochKey: hex(v["epoch_key"] as! String),
                poleValue: hex(v["pole_value"] as! String), prevKey: hex(v["prev_key"] as! String),
                contextSeparator: hex(v["context_separator"] as! String), drandRound: hex(v["drand_round"] as! String))
            XCTAssertEqual(try sk.key, hex(v["output"] as! String))
        }
    }

    func testContextKey() throws {
        for v in arr(try vectors(), "context_key") {
            let sk = SessionKey(drandRound: Data(count: 8), key: hex(v["session_key"] as! String))
            XCTAssertEqual(try sk.contextKey(v["context"] as! String), hex(v["output"] as! String))
        }
    }

    func testHandle() throws {
        for v in arr(try vectors(), "handle_of") {
            XCTAssertEqual(handleOf(hex(v["public_encoded"] as! String)), hex(v["output"] as! String))
        }
    }

    func testRecognition() throws {
        for v in arr(try vectors(), "recognition") {
            let beacon = hex(v["beacon"] as! String)
            let (aPriv, aPub) = Recognition.contribution(sessionKey: hex(v["session_key_a"] as! String), beacon: beacon)
            let (_, bPub) = Recognition.contribution(sessionKey: hex(v["session_key_b"] as! String), beacon: beacon)
            XCTAssertEqual(aPub.publicKey, hex(v["a_pub"] as! String), "X25519 pubkey derivation diverged")
            XCTAssertEqual(bPub.publicKey, hex(v["b_pub"] as! String))
            let rec = Recognition.value(myPriv: aPriv, theirPub: bPub.publicKey, myPub: aPub.publicKey, beacon: beacon)
            XCTAssertEqual(rec, hex(v["recognition"] as! String))
        }
    }

    func testTunnelEvolve() throws {
        for v in arr(try vectors(), "tunnel_evolve") {
            XCTAssertEqual(Recognition.evolveTunnelKey(hex(v["prev"] as! String), recognition: hex(v["recognition"] as! String)),
                           hex(v["output"] as! String))
        }
    }

    func testLedger() throws {
        for v in arr(try vectors(), "ledger_entry") {
            let ledger = LedgerStub()
            let r = ledger.anchor(hex(v["content_hash"] as! String))
            XCTAssertEqual(r.entryHash, hex(v["entry_hash"] as! String))
            XCTAssertEqual(r.index, v["index"] as! Int)
        }
    }

    func testPAD() throws {
        for v in arr(try vectors(), "pad") {
            let depth = (v["depth_map"] as! [NSNumber]).map { $0.doubleValue }
            let r = PAD.check(depthMap: depth, moireScore: (v["moire"] as! NSNumber).doubleValue)
            XCTAssertEqual(r.passed, v["passed"] as! Bool)
            XCTAssertEqual(r.depthVariance, (v["depth_variance"] as! NSNumber).doubleValue, accuracy: 1e-9)
            XCTAssertEqual(r.digest(), hex(v["digest"] as! String))
        }
    }

    func testTokenMAC() throws {
        for v in arr(try vectors(), "token_mac") {
            let payload = CapabilityToken.payload(scope: v["scope"] as! String, purpose: v["purpose"] as! String,
                                                  expiry: (v["expiry"] as! NSNumber).doubleValue, nonce: v["nonce"] as! String)
            XCTAssertEqual(String(data: payload, encoding: .utf8), v["canonical_payload"] as? String)
            let mac = HMAC<SHA256>.authenticationCode(for: payload, using: SymmetricKey(data: hex(v["session_key"] as! String)))
            XCTAssertEqual(Data(mac).hexString, v["mac"] as! String)
        }
    }

    func testMetadataCanonical() throws {
        for v in arr(try vectors(), "capture_metadata_canonical") {
            let meta = CaptureMetadata(cameraIntrinsics: v["camera_intrinsics"] as! String, motion: v["motion"] as! String,
                                       capturedAt: v["captured_at"] as! String, depthSummary: v["depth_summary"] as! String)
            XCTAssertEqual(String(data: meta.canonical(), encoding: .utf8), v["canonical"] as? String)
            XCTAssertEqual(Primitives.H(Data("atlas/meta-test".utf8), meta.canonical()), hex(v["hash"] as! String))
        }
    }

    /// X-Wing hybrid-KEM combiner transcript — pins the 5-element order
    /// [ssMLKEM, ssX, mlkemCT, xEphPK, recipientXPK]. Catches a combiner that
    /// drops the ciphertext (which would make phone<->Mac tunnel keys diverge).
    func testXWingCombine() throws {
        for v in arr(try vectors(), "xwing_combine") {
            let out = Primitives.hkdfCombine(
                [hex(v["ss_mlkem"] as! String), hex(v["ss_x"] as! String), hex(v["mlkem_ct"] as! String),
                 hex(v["x_eph_pk"] as! String), hex(v["recipient_x_pk"] as! String)],
                info: Data((v["label"] as! String).utf8), length: 32)
            XCTAssertEqual(out, hex(v["output"] as! String), "X-Wing combiner transcript diverged")
        }
    }

    // MARK: - Priority 2 parity: split-TSK identity, presence unwrap, live binding

    func testIdentityTreeSplitTSK() throws {
        for v in arr(try vectors(), "identity_tree_split_tsk") {
            let (uh, sh) = tskHalves(tskSeed: hex(v["tsk_seed"] as! String), rotation: v["rotation"] as! Int)
            XCTAssertEqual(uh, hex(v["user_half"] as! String), "user half diverged")
            XCTAssertEqual(sh, hex(v["server_half"] as! String), "server half diverged")
            let sid = reassembleSystemID(userHalf: uh, serverHalf: sh)
            XCTAssertEqual(sid, hex(v["system_id"] as! String), "System-ID reassembly diverged")
            XCTAssertEqual(Primitives.H(Data("atlas/system-id-handle".utf8), sid),
                           hex(v["system_id_handle"] as! String))
            for (ctx, exp) in (v["child_seeds"] as! [String: String]) {
                let got = Primitives.hkdf(ikm: sid, info: Data("atlas/child/\(ctx)/0".utf8), length: 32)
                XCTAssertEqual(got, hex(exp), "child seed \(ctx) diverged")
            }
            for (key, exp) in (v["pseudonym_seeds"] as! [String: String]) {
                let parts = key.split(separator: ":", maxSplits: 1).map(String.init)
                let got = Primitives.hkdf(ikm: sid,
                                          info: Data("atlas/pseudonym/\(parts[0])/\(parts[1])".utf8), length: 32)
                XCTAssertEqual(got, hex(exp), "pseudonym seed \(key) diverged")
            }
        }
    }

    func testPresenceUnwrapChain() throws {
        for v in arr(try vectors(), "presence_unwrap_chain") {
            let eid = hex(v["drand_round"] as! String)
            // pure-HKDF unwrap/lk key derivations (info labels are epoch-scoped)
            let unwrapK = Primitives.hkdf(ikm: hex(v["enrollment_secret"] as! String),
                                          info: Data("atlas/epoch-unwrap|".utf8) + eid, length: 32)
            XCTAssertEqual(unwrapK, hex(v["unwrap_key"] as! String), "epoch unwrap key diverged")
            let lkK = Primitives.hkdf(ikm: hex(v["epoch_key"] as! String),
                                      info: Data("atlas/lk-unlock|".utf8) + eid, length: 32)
            XCTAssertEqual(lkK, hex(v["lk_key"] as! String), "lk unlock key diverged")
            // full decrypt round-trip against the committed fixed-nonce blobs
            let ek = try Presence.unwrapEpochKey(hex(v["wrapped_epoch_key"] as! String),
                                                 presenceSecret: hex(v["enrollment_secret"] as! String), drandRound: eid)
            XCTAssertEqual(ek, hex(v["epoch_key"] as! String), "epoch-key unwrap round-trip diverged")
            let lk = try Presence.unlockLK(hex(v["wrapped_lk"] as! String),
                                           epochKey: hex(v["epoch_key"] as! String), drandRound: eid)
            XCTAssertEqual(lk, hex(v["lk"] as! String), "LK unlock round-trip diverged")
        }
    }

    /// Live-provenance binding cores (Priority 1 / T-25b). The Swift live_binding
    /// module is not yet ported (see ios/RESYNC_NOTES.md); these pins prove the
    /// pure-H() cores byte-for-byte so the future port's witness signature will
    /// verify against Python-produced bindings.
    func testLiveProvenanceBinding() throws {
        for v in arr(try vectors(), "live_provenance_binding") {
            let lk = hex(v["lk"] as! String), eid = hex(v["drand_round"] as! String)
            let ch = hex(v["content_hash"] as! String), handle = hex(v["authorship_handle"] as! String)
            let witnessSeed = Primitives.H(Data("atlas/lk-witness".utf8), lk, eid)
            XCTAssertEqual(witnessSeed, hex(v["witness_seed"] as! String), "witness seed diverged")
            let sc = Primitives.H(Data("atlas/prov/session-commit".utf8), hex(v["session_key"] as! String), ch)
            XCTAssertEqual(sc, hex(v["session_commit"] as! String), "session commit diverged")
            let core = Primitives.H(Data("atlas/prov/attribution-core".utf8), ch, eid, handle, sc)
            XCTAssertEqual(core, hex(v["attribution_core"] as! String), "attribution core diverged")
        }
    }

    // MARK: - Threshold biometric-key seal parity (TRUST_LAYER.md #1/#2)

    /// The new parity-critical derivation: unlock key = HKDF(userHalf || custodianSecret).
    func testThresholdUnlockKey() throws {
        for v in arr(try vectors(), "threshold_unlock_key") {
            let out = ThresholdSeal.unlockKey(userHalf: hex(v["user_half"] as! String),
                                              custodianSecret: hex(v["custodian_secret"] as! String),
                                              context: hex(v["context"] as! String))
            XCTAssertEqual(out, hex(v["output"] as! String), "threshold unlock key diverged")
        }
    }

    /// Full cross-impl interop: Python sealed the sketch, Swift must reopen it with the user
    /// half + any m-of-n shares — and stay fail-closed below threshold.
    func testThresholdSealCrossImpl() throws {
        for v in arr(try vectors(), "threshold_seal") {
            let m = v["m"] as! Int
            let policy = try ThresholdSeal.ThresholdPolicy(n: v["n"] as! Int, m: m)
            let shares = (v["shares"] as! [[String: Any]]).enumerated().map { (i, s) in
                ThresholdSeal.CustodianShare(
                    custodian: ThresholdSeal.Custodian(label: "c\(i)"),
                    share: Shamir.Share(index: UInt8(s["index"] as! Int), y: hex(s["y"] as! String)))
            }
            let sealed = ThresholdSeal.SealedSketch(ciphertext: hex(v["ciphertext"] as! String),
                                                    storage: .selfCustody, policy: policy,
                                                    context: hex(v["context"] as! String))
            let userHalf = hex(v["user_half"] as! String)
            let out = try ThresholdSeal.unseal(sealed, userHalf: userHalf,
                                               custodianShares: Array(shares.prefix(m)))
            XCTAssertEqual(out, hex(v["plaintext"] as! String), "cross-impl unseal diverged")
            XCTAssertThrowsError(try ThresholdSeal.unseal(sealed, userHalf: userHalf,
                                                          custodianShares: Array(shares.prefix(m - 1))))
        }
    }

    /// The Swift seal path itself round-trips and is fail-closed on a wrong user half.
    func testThresholdSealNativeRoundTrip() throws {
        let policy = try ThresholdSeal.ThresholdPolicy(n: 5, m: 3)
        let custodians = (0..<5).map { ThresholdSeal.Custodian(label: "c\($0)") }
        let secret = Data("native-round-trip-secret".utf8)
        let ctx = Data("native-ctx".utf8)
        let (sealed, shares) = try ThresholdSeal.seal(secret, userHalf: Data("uh".utf8),
            custodians: custodians, policy: policy, storage: .guardians, context: ctx)
        XCTAssertEqual(try ThresholdSeal.unseal(sealed, userHalf: Data("uh".utf8),
                                                custodianShares: Array(shares.prefix(3))), secret)
        XCTAssertThrowsError(try ThresholdSeal.unseal(sealed, userHalf: Data("wrong".utf8),
                                                      custodianShares: Array(shares.prefix(3))))
    }

    // MARK: - Ledger parity (TRUST_LAYER.md #8/#9)

    func testMerkleTree() throws {
        for v in arr(try vectors(), "merkle_tree") {
            let leaves = (v["leaves"] as! [String]).map { hex($0) }
            let root = hex(v["root"] as! String)
            XCTAssertEqual(Merkle.root(leaves), root, "merkle root diverged")
            XCTAssertEqual(Merkle.emptyRoot(), hex(v["empty_root"] as! String))
            XCTAssertEqual(Merkle.leafHash(leaves[0]), hex(v["leaf0_hash"] as! String))
            for p in (v["proofs"] as! [[String: Any]]) {
                let path: [Merkle.ProofStep] = (p["path"] as! [[String: Any]]).map {
                    (hex($0["sibling"] as! String), $0["right"] as! Bool)
                }
                XCTAssertTrue(Merkle.verifyInclusion(hex(p["leaf"] as! String), proof: path, root: root),
                              "merkle inclusion diverged at index \(p["index"] as! Int)")
            }
        }
    }

    func testLedgerCommit() throws {
        for v in arr(try vectors(), "ledger_commit") {
            let (c, _) = LedgerCommit.commit(hex(v["content"] as! String), opening: hex(v["opening"] as! String))
            XCTAssertEqual(c, hex(v["commitment"] as! String), "ledger commitment diverged")
        }
    }

    func testGlobalAnchorEntry() throws {
        for v in arr(try vectors(), "global_anchor") {
            var ib = UInt64(v["index"] as! Int).bigEndian
            let eh = Primitives.H(Data("atlas/global-anchor".utf8), hex(v["prev"] as! String),
                                  GlobalAnchorLog.lp(hex(v["owner_id"] as! String)),
                                  GlobalAnchorLog.lp(hex(v["root"] as! String)),
                                  GlobalAnchorLog.lp(hex(v["drand_round"] as! String)),
                                  withUnsafeBytes(of: &ib) { Data($0) })
            XCTAssertEqual(eh, hex(v["entry_hash"] as! String), "global anchor entry hash diverged")
        }
    }

    func testSpacePseudonym() throws {
        for v in arr(try vectors(), "space_pseudonym") {
            let root = hex(v["root"] as! String), space = hex(v["space_id"] as! String)
            XCTAssertEqual(SpacePseudonym.spaceNym(root: root, spaceID: space),
                           hex(v["nym"] as! String), "space nym diverged")
            XCTAssertEqual(SpacePseudonym.spaceNullifier(root: root, spaceID: space),
                           hex(v["nullifier"] as! String), "space nullifier diverged")
        }
    }

    func testDeviceAttestation() throws {
        for v in arr(try vectors(), "device_attestation") {
            let deviceID = hex(v["device_id"] as! String)
            for c in (v["cases"] as! [[String: Any]]) {
                let caps = TrustedDevice.Capability(rawValue: c["capabilities"] as! Int)
                let tier = TrustedDevice.assuranceTier(caps)
                XCTAssertEqual(tier.rawValue, c["tier"] as! Int, "assurance tier diverged")
                XCTAssertEqual(TrustedDevice.attestationDigest(deviceID: deviceID, capabilities: caps, tier: tier),
                               hex(c["digest"] as! String), "attestation digest diverged")
            }
        }
    }

    func testCryptoSuite() throws {
        for v in arr(try vectors(), "crypto_suite") {
            let s = CryptoAgility.CryptoSuite(version: v["version"] as! Int, kem: v["kem"] as! String,
                                              signature: v["signature"] as! String,
                                              credential: v["credential"] as! String)
            XCTAssertEqual(s.suiteId(), hex(v["suite_id"] as! String), "crypto suite id diverged")
        }
    }

    func testSpaceVaultKey() throws {
        for v in arr(try vectors(), "space_vault_key") {
            XCTAssertEqual(Spaces.vaultKey(spaceRoot: hex(v["space_root"] as! String),
                                           spaceID: hex(v["space_id"] as! String)),
                           hex(v["vault_key"] as! String), "space vault key diverged")
        }
    }

    func testAttestationClaim() throws {
        for v in arr(try vectors(), "attestation_claim") {
            let cap = TrustedDevice.Capability(rawValue: v["capability"] as! Int)
            let dev = hex(v["device_id"] as! String), chal = hex(v["challenge"] as! String)
            XCTAssertEqual(TrustedDevice.claimMessage(deviceID: dev, capability: cap, challenge: chal),
                           hex(v["message"] as! String), "attestation claim message diverged")
            // verify the Python-produced Ed25519 signature in Swift (cross-impl RFC 8032)
            XCTAssertTrue(TrustedDevice.verifyClaim(attestorPublic: hex(v["attestor_public"] as! String),
                deviceID: dev, capability: cap, challenge: chal, signature: hex(v["signature"] as! String)),
                "cross-impl Ed25519 attestation verify failed")
        }
    }

    func testAuthorityGrant() throws {
        for v in arr(try vectors(), "authority_grant") {
            let rights = Authority.RightSet(v["level"] as! Int, Set(v["flags"] as! [String]))
            var caveats = Set<Authority.Caveat>()
            for c in (v["caveats"] as! [[String: Any]]) {
                caveats.insert(Authority.Caveat(c["key"] as! String, c["value"] as! String))
            }
            let gid = Authority.grantId(
                grantorEnc: hex(v["grantor"] as! String), granteeEnc: hex(v["grantee"] as! String),
                resource: hex(v["resource"] as! String), rights: rights, caveats: caveats,
                depth: v["depth"] as! Int, parent: hex(v["parent"] as! String),
                epoch: UInt64(v["epoch"] as! Int))
            XCTAssertEqual(gid, hex(v["grant_id"] as! String), "authority grant_id diverged")
        }
    }

    func testAuthorityRightsAndCaveatEncode() throws {
        for v in arr(try vectors(), "authority_rights_encode") {
            let r = Authority.RightSet(v["level"] as! Int, Set(v["flags"] as! [String]))
            XCTAssertEqual(r.encode(), hex(v["output"] as! String), "authority rights encode diverged")
        }
        for v in arr(try vectors(), "authority_caveat_encode") {
            let c = Authority.Caveat(v["key"] as! String, v["value"] as! String)
            XCTAssertEqual(c.encode(), hex(v["output"] as! String), "authority caveat encode diverged")
        }
    }

    func testFSMerkleGlue() throws {
        for v in arr(try vectors(), "fs_leaf_hash") {
            XCTAssertEqual(FSSign.leafHash(hex(v["leaf_public"] as! String)), hex(v["output"] as! String))
        }
        for v in arr(try vectors(), "fs_node") {
            XCTAssertEqual(FSSign.node(hex(v["left"] as! String), hex(v["right"] as! String)),
                           hex(v["output"] as! String))
        }
        for v in arr(try vectors(), "fs_root_from_path") {
            let path = (v["auth_path"] as! [String]).map { hex($0) }
            XCTAssertEqual(FSSign.rootFromPath(hex(v["leaf_hash"] as! String), v["index"] as! Int, path),
                           hex(v["root"] as! String), "fs root-from-path diverged")
        }
    }

    /// Market + Feed (Phase B #2): the domain-separated, length-prefixed bodies that Receipt /
    /// Review / Endorsement sign over. If these match Python, a review written on one impl verifies
    /// on the other. Public keys are supplied as fixed bytes, so this is independent of keygen.
    func testMarketBodies() throws {
        for v in arr(try vectors(), "market_review_content_hash") {
            XCTAssertEqual(Primitives.H(Data("atlas/market/review-content".utf8), hex(v["content"] as! String)),
                           hex(v["output"] as! String), "review content-hash diverged")
        }
        for v in arr(try vectors(), "market_receipt_body") {
            let r = Spaces.Receipt(seller: HybridSign.PublicKey(encoded: hex(v["seller"] as! String))!,
                                   buyer: HybridSign.PublicKey(encoded: hex(v["buyer"] as! String))!,
                                   item: hex(v["item"] as! String), epoch: UInt64(v["epoch"] as! Int))
            XCTAssertEqual(Primitives.H(r.body()), hex(v["output"] as! String), "receipt body diverged")
        }
        for v in arr(try vectors(), "market_review_body") {
            let r = Spaces.Review(reviewer: HybridSign.PublicKey(encoded: hex(v["reviewer"] as! String))!,
                                  item: hex(v["item"] as! String), rating: v["rating"] as! Int,
                                  contentHash: hex(v["content_hash"] as! String),
                                  epoch: UInt64(v["epoch"] as! Int))
            XCTAssertEqual(Primitives.H(r.body()), hex(v["output"] as! String), "review body diverged")
        }
        for v in arr(try vectors(), "market_endorse_body") {
            let e = Spaces.Endorsement(endorser: HybridSign.PublicKey(encoded: hex(v["endorser"] as! String))!,
                                       target: hex(v["target"] as! String), epoch: UInt64(v["epoch"] as! Int))
            XCTAssertEqual(Primitives.H(e.body()), hex(v["output"] as! String), "endorse body diverged")
        }
    }

    /// Polls: poll_id (H over the signed poll body) + the ballot body must frame identically so a poll
    /// has the same id on every impl and a ballot verifies cross-impl.
    func testPollBodies() throws {
        for v in arr(try vectors(), "poll_id") {
            let opts = (v["options"] as! [String]).map { hex($0) }
            let p = Spaces.Poll(author: HybridSign.PublicKey(encoded: hex(v["author"] as! String))!,
                                question: hex(v["question"] as! String), options: opts,
                                tier: Spaces.IdentityTier(rawValue: v["tier"] as! Int)!,
                                epoch: v["epoch"] as! Int)
            XCTAssertEqual(p.pollID(), hex(v["output"] as! String), "poll_id diverged")
        }
        for v in arr(try vectors(), "poll_response_body") {
            let r = Spaces.PollResponse(pollID: hex(v["poll_id"] as! String), choice: v["choice"] as! Int,
                                        nullifier: hex(v["nullifier"] as! String),
                                        ballotKey: HybridSign.PublicKey(encoded: hex(v["ballot_key"] as! String))!,
                                        epoch: v["epoch"] as! Int)
            XCTAssertEqual(Primitives.H(r.body()), hex(v["output"] as! String), "poll response body diverged")
        }
    }

    /// Soul-bound token: token_id (H over the signed body) must frame identically so an SBT has the
    /// same id on every impl and a collected token verifies cross-impl.
    func testSoulboundTokenID() throws {
        for v in arr(try vectors(), "soulbound_token_id") {
            let t = Participation.SoulboundToken(
                holder: HybridSign.PublicKey(encoded: hex(v["holder"] as! String))!,
                kind: hex(v["kind"] as! String),
                issuer: HybridSign.PublicKey(encoded: hex(v["issuer"] as! String))!,
                epoch: v["epoch"] as! Int, payload: hex(v["payload"] as! String))
            XCTAssertEqual(t.tokenID(), hex(v["output"] as! String), "soulbound token_id diverged")
        }
    }

}
