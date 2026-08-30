import Foundation
import CryptoKit

/// Signatures (§1.3, ATLAS VIII §B.2). Mirrors `backend/atlas/crypto/sign.py`.
///
///  * Routine signatures (beacon, proof tokens, attestations, provenance):
///    hybrid ML-DSA-65 + Ed25519 — a verifier accepts only if BOTH verify.
///  * Long-lived root / TSK: SPHINCS+ (SLH-DSA), standalone.
///
/// FALCON is intentionally absent (ring SE only; not on the R10, §0.3).
///
/// ════════════════════════════════════════════════════════════════════════
///  VERIFY-AGAINST-SDK: `MLDSA65` reflects CryptoKit's 2025 PQC API. SPHINCS+ is
///  not yet a first-class CryptoKit type on all SDKs; `SphincsPlus` below is the
///  seam — back it with CryptoKit's SLH-DSA when available, or a vendored
///  implementation, or (production) the on-card/HSM root. The TSK only signs
///  rare continuity events, so a software SLH-DSA is acceptable for the PoC.
/// ════════════════════════════════════════════════════════════════════════
public enum HybridSign {

    public struct PublicKey: Sendable, Equatable {
        public let mldsaPK: Data
        public let edPK: Data
        public init(mldsaPK: Data, edPK: Data) { self.mldsaPK = mldsaPK; self.edPK = edPK }

        /// Inverse of `encode()` — reconstruct from length-prefixed bytes.
        public init?(encoded: Data) {
            var off = encoded.startIndex
            func chunk() -> Data? {
                guard off + 4 <= encoded.endIndex else { return nil }
                let n = Int(encoded.subdata(in: off..<off+4).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian })
                off += 4
                guard off + n <= encoded.endIndex else { return nil }
                let c = encoded.subdata(in: off..<off+n); off += n; return c
            }
            guard let m = chunk(), let e = chunk() else { return nil }
            self.mldsaPK = m; self.edPK = e
        }

        /// Length-prefixed encoding used for handles (must match identity.py).
        public func encode() -> Data {
            var out = Data()
            var n1 = UInt32(mldsaPK.count).bigEndian; withUnsafeBytes(of: &n1) { out.append(contentsOf: $0) }
            out.append(mldsaPK)
            var n2 = UInt32(edPK.count).bigEndian; withUnsafeBytes(of: &n2) { out.append(contentsOf: $0) }
            out.append(edPK)
            return out
        }
    }

    public struct Keypair {
        public let mldsa: MLDSA65.PrivateKey
        public let ed: Curve25519.Signing.PrivateKey
        public var publicKey: PublicKey {
            PublicKey(mldsaPK: mldsa.publicKey.rawRepresentation, edPK: ed.publicKey.rawRepresentation)
        }
    }

    public static func generate() -> Keypair {
        // MLDSA65.PrivateKey() throws in the shipping SDK; random keygen only fails
        // catastrophically, so try! keeps the non-throwing API contract.
        Keypair(mldsa: try! MLDSA65.PrivateKey(), ed: Curve25519.Signing.PrivateKey())
    }

    /// Deterministic child keypair from a 32-byte seed (identity tree, §7).
    /// Independent coins per component so neither leaks the other.
    public static func keypair(fromSeed seed: Data) throws -> Keypair {
        precondition(seed.count >= 32)
        let mldsaSeed = Primitives.hkdf(ikm: seed, info: Data("atlas/sig-seed/mldsa".utf8), length: 32)
        let edSeed = Primitives.hkdf(ikm: seed, info: Data("atlas/sig-seed/ed25519".utf8), length: 32)
        // MLDSA65.PrivateKey(seedRepresentation:publicKey:) — deterministic keygen
        // from a seed/xi; publicKey nil = derive it from the seed.
        let mldsa = try MLDSA65.PrivateKey(seedRepresentation: mldsaSeed, publicKey: nil)
        let ed = try Curve25519.Signing.PrivateKey(rawRepresentation: edSeed)
        return Keypair(mldsa: mldsa, ed: ed)
    }

    public static func sign(_ kp: Keypair, _ message: Data) throws -> Data {
        let sM = try kp.mldsa.signature(for: message)
        let sE = try kp.ed.signature(for: message)
        var out = Data()
        var n1 = UInt32(sM.count).bigEndian; withUnsafeBytes(of: &n1) { out.append(contentsOf: $0) }
        out.append(sM)
        var n2 = UInt32(sE.count).bigEndian; withUnsafeBytes(of: &n2) { out.append(contentsOf: $0) }
        out.append(sE)
        return out
    }

    public static func verify(_ pub: PublicKey, _ message: Data, _ signature: Data) -> Bool {
        var off = signature.startIndex
        func readChunk() -> Data? {
            guard off + 4 <= signature.endIndex else { return nil }
            let n = Int(signature.subdata(in: off..<off+4).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian })
            off += 4
            guard off + n <= signature.endIndex else { return nil }
            let c = signature.subdata(in: off..<off+n); off += n; return c
        }
        guard let sM = readChunk(), let sE = readChunk() else { return false }
        do {
            let mPub = try MLDSA65.PublicKey(rawRepresentation: pub.mldsaPK)
            guard mPub.isValidSignature(sM, for: message) else { return false }
            let ePub = try Curve25519.Signing.PublicKey(rawRepresentation: pub.edPK)
            return ePub.isValidSignature(sE, for: message)
        } catch { return false }
    }
}

/// SPHINCS+ / SLH-DSA seam for the TSK root (§2.1, §7.1). See VERIFY note above.
public protocol SphincsProvider {
    func keypair(fromSeed seed: Data) -> (publicKey: Data, secretKey: Data)
    func sign(secretKey: Data, message: Data) -> Data
    func verify(publicKey: Data, message: Data, signature: Data) -> Bool
}
