// Built 2026-08-08 as the engine of the in-app System Health Monitor (the app's
// "run a full system check on-device, automatically" surface). Paired with
// AtlasApp/UI/SystemHealthView.swift (Health tab). Roadmap: expand to the full
// parity set + pure-software roundtrips, then a tamper-evident SE-signed
// SessionRecorder log, then Tier-B guided hardware checks (Face ID / ring / attest).
import Foundation
import CryptoKit

/// In-app system health check (Inv 14 "conformance to earn" / Math Spec §38).
///
/// Runs the pure-software conformance checks *from the running app, on the actual
/// device* — most importantly the cross-implementation PARITY vectors: proof that
/// this device's Swift crypto is byte-identical to the Python reference-of-record.
/// `swift test` proves the code is correct on a Mac; this proves it on the phone.
///
/// Tier A here is fully automatic (no human, no hardware). Hardware-gated checks
/// (Secure Enclave release under Face ID, ring pulse, App Attest) are Tier B and
/// are driven from the app layer with the human in the loop — they are NOT here.
///
/// Discipline: every result is a pass/fail + a count. No secret key material, no
/// raw biosignal, and no plaintext ever appears in a result — only verdicts.
public enum SystemCheck {

    public struct Result: Sendable, Identifiable {
        public let id = UUID()
        public let name: String
        public let passed: Int
        public let total: Int
        public let detail: String
        /// A category is OK only if every vector matched AND there was at least one.
        public var ok: Bool { total > 0 && passed == total }
    }

    /// Tier A: run every bundled parity category on this device. Returns one Result
    /// per category. `SystemCheck.run().allSatisfy(\.ok)` == "this device's crypto is
    /// byte-identical to the Python reference."
    public static func run() -> [Result] {
        guard
            let url = Bundle.module.url(forResource: "parity_vectors", withExtension: "json"),
            let data = try? Data(contentsOf: url),
            let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else {
            return [Result(name: "parity_vectors.json", passed: 0, total: 0,
                           detail: "not bundled — cannot run on-device parity")]
        }

        func vectors(_ key: String) -> [[String: Any]] { (root[key] as? [[String: Any]]) ?? [] }
        func hx(_ s: String) -> Data { Data(hex: s) }

        var results: [Result] = []
        func category(_ key: String, _ name: String, _ check: ([String: Any]) -> Bool) {
            let vs = vectors(key)
            var pass = 0
            for v in vs { if check(v) { pass += 1 } }
            results.append(Result(name: name, passed: pass, total: vs.count, detail: "\(pass)/\(vs.count) vectors"))
        }

        // --- core crypto chain (the load-bearing derivations) --------------------
        category("sha3_256", "SHA3-256") { v in
            SHA3.sha3_256(hx(v["input"] as! String)) == hx(v["output"] as! String)
        }
        category("hkdf", "HKDF") { v in
            Primitives.hkdf(ikm: hx(v["ikm"] as! String), info: hx(v["info"] as! String),
                            length: v["length"] as! Int) == hx(v["output"] as! String)
        }
        category("hkdf_combine", "HKDF-combine") { v in
            let parts = (v["parts"] as! [String]).map { hx($0) }
            return Primitives.hkdfCombine(parts, info: hx(v["info"] as! String),
                                          length: v["length"] as! Int) == hx(v["output"] as! String)
        }
        category("aes256gcm_fixed_nonce", "AES-256-GCM (AEAD)") { v in
            let key = SymmetricKey(data: hx(v["key"] as! String))
            guard
                let nonce = try? AES.GCM.Nonce(data: hx(v["nonce"] as! String)),
                let sealed = try? AES.GCM.seal(hx(v["plaintext"] as! String), using: key,
                                               nonce: nonce, authenticating: hx(v["aad"] as! String))
            else { return false }
            return sealed.ciphertext + sealed.tag == hx(v["ciphertext_and_tag"] as! String)
        }
        category("ratchet", "Forward-secret ratchet") { v in
            Derivation.ratchet(hx(v["prev"] as! String), entropyT: hx(v["entropy"] as! String),
                               beaconT: hx(v["beacon"] as! String),
                               epochRound: hx(v["epoch_round"] as! String)) == hx(v["output"] as! String)
        }
        category("session_key_decoupled", "Session key (decoupled)") { v in
            let sk = Derivation.sessionKeyDecoupled(
                lk: hx(v["lk"] as! String), epochKey: hx(v["epoch_key"] as! String),
                poleValue: hx(v["pole_value"] as! String), prevKey: hx(v["prev_key"] as! String),
                contextSeparator: hx(v["context_separator"] as! String),
                epochRound: hx(v["epoch_round"] as! String))
            guard let k = try? sk.key else { return false }
            return k == hx(v["output"] as! String)
        }
        category("xwing_combine", "X-Wing KEM combiner") { v in
            Primitives.hkdfCombine(
                [hx(v["ss_mlkem"] as! String), hx(v["ss_x"] as! String), hx(v["mlkem_ct"] as! String),
                 hx(v["x_eph_pk"] as! String), hx(v["recipient_x_pk"] as! String)],
                info: Data((v["label"] as! String).utf8), length: 32) == hx(v["output"] as! String)
        }

        // --- capability tokens ---------------------------------------------------
        category("token_mac", "Capability tokens") { v in
            let payload = CapabilityToken.payload(scope: v["scope"] as! String, purpose: v["purpose"] as! String,
                                                  expiry: (v["expiry"] as! NSNumber).doubleValue, nonce: v["nonce"] as! String)
            guard String(data: payload, encoding: .utf8) == (v["canonical_payload"] as? String) else { return false }
            let mac = HMAC<SHA256>.authenticationCode(for: payload, using: SymmetricKey(data: hx(v["session_key"] as! String)))
            return Data(mac).hexString == (v["mac"] as! String)
        }
        // --- per-space pseudonyms (unlinkability) --------------------------------
        category("space_pseudonym", "Pseudonym unlinkability") { v in
            let root = hx(v["root"] as! String), space = hx(v["space_id"] as! String)
            return SpacePseudonym.spaceNym(root: root, spaceID: space) == hx(v["nym"] as! String)
                && SpacePseudonym.spaceNullifier(root: root, spaceID: space) == hx(v["nullifier"] as! String)
        }
        // --- ledger / Merkle inclusion -------------------------------------------
        category("merkle_tree", "Ledger (Merkle)") { v in
            let leaves = (v["leaves"] as! [String]).map { hx($0) }
            let root = hx(v["root"] as! String)
            guard Merkle.root(leaves) == root,
                  Merkle.emptyRoot() == hx(v["empty_root"] as! String),
                  Merkle.leafHash(leaves[0]) == hx(v["leaf0_hash"] as! String) else { return false }
            for p in (v["proofs"] as! [[String: Any]]) {
                let path: [Merkle.ProofStep] = (p["path"] as! [[String: Any]]).map {
                    (hx($0["sibling"] as! String), $0["right"] as! Bool)
                }
                if !Merkle.verifyInclusion(hx(p["leaf"] as! String), proof: path, root: root) { return false }
            }
            return true
        }
        // --- presence gate: epoch-key unwrap → LK unlock (the liveness gate) ------
        category("presence_unwrap_chain", "Presence gate (unwrap chain)") { v in
            let eid = hx(v["epoch_round"] as! String)
            guard Primitives.hkdf(ikm: hx(v["enrollment_secret"] as! String),
                                  info: Data("atlas/epoch-unwrap|".utf8) + eid, length: 32) == hx(v["unwrap_key"] as! String),
                  Primitives.hkdf(ikm: hx(v["epoch_key"] as! String),
                                  info: Data("atlas/lk-unlock|".utf8) + eid, length: 32) == hx(v["lk_key"] as! String),
                  let ek = try? Presence.unwrapEpochKey(hx(v["wrapped_epoch_key"] as! String),
                                    presenceSecret: hx(v["enrollment_secret"] as! String), epochRound: eid),
                  ek == hx(v["epoch_key"] as! String),
                  let lk = try? Presence.unlockLK(hx(v["wrapped_lk"] as! String),
                                    epochKey: hx(v["epoch_key"] as! String), epochRound: eid),
                  lk == hx(v["lk"] as! String)
            else { return false }
            return true
        }
        // --- device attestation tiers --------------------------------------------
        category("device_attestation", "Device attestation") { v in
            let deviceID = hx(v["device_id"] as! String)
            for c in (v["cases"] as! [[String: Any]]) {
                let caps = TrustedDevice.Capability(rawValue: c["capabilities"] as! Int)
                let tier = TrustedDevice.assuranceTier(caps)
                guard tier.rawValue == c["tier"] as! Int,
                      TrustedDevice.attestationDigest(deviceID: deviceID, capabilities: caps, tier: tier) == hx(c["digest"] as! String)
                else { return false }
            }
            return true
        }
        // --- split-TSK identity tree ---------------------------------------------
        category("identity_tree_split_tsk", "Identity tree (split-TSK)") { v in
            let (uh, sh) = tskHalves(tskSeed: hx(v["tsk_seed"] as! String), rotation: v["rotation"] as! Int)
            guard uh == hx(v["user_half"] as! String), sh == hx(v["server_half"] as! String) else { return false }
            let sid = reassembleSystemID(userHalf: uh, serverHalf: sh)
            guard sid == hx(v["system_id"] as! String) else { return false }
            for (ctx, exp) in (v["child_seeds"] as! [String: String]) {
                if Primitives.hkdf(ikm: sid, info: Data("atlas/child/\(ctx)/0".utf8), length: 32) != hx(exp) { return false }
            }
            return true
        }

        return results
    }

    /// One-line health summary: "N/M categories pass (K/K vectors)".
    public static func summary(_ results: [Result]) -> String {
        let okCount = results.filter(\.ok).count
        let vecPass = results.reduce(0) { $0 + $1.passed }
        let vecTotal = results.reduce(0) { $0 + $1.total }
        return "\(okCount)/\(results.count) categories · \(vecPass)/\(vecTotal) vectors"
    }
}
