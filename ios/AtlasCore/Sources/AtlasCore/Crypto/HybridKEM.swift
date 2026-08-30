import Foundation
import CryptoKit

/// Hybrid KEM — X-Wing-style ML-KEM-768 + X25519 (§1.3, ATLAS VIII §B.2).
/// Mirrors `backend/atlas/crypto/kem.py`. The combiner is byte-identical to the
/// Python core so the two ends interoperate.
///
/// ════════════════════════════════════════════════════════════════════════
///  VERIFY-AGAINST-SDK: the ML-KEM symbol names below reflect CryptoKit's
///  quantum-secure API as introduced in the 2025 SDKs. Apple also ships a
///  ready-made `XWingMLKEM768X25519` type; if you adopt it, replace
///  `encapsulate`/`decapsulate` with that type AND change the Python core to the
///  RFC X-Wing combiner so both ends still match. As written, this is an
///  *X-Wing-style* HKDF combiner over ML-KEM-768 ⊕ X25519, matching kem.py.
/// ════════════════════════════════════════════════════════════════════════
public enum HybridKEM {

    public struct PublicKey: Sendable {
        public let mlkemEK: Data        // ML-KEM encapsulation (public) key
        public let x25519PK: Data       // raw 32-byte X25519 public key
        public init(mlkemEK: Data, x25519PK: Data) { self.mlkemEK = mlkemEK; self.x25519PK = x25519PK }
    }

    public struct Keypair {
        public let mlkem: MLKEM768.PrivateKey
        public let x25519: Curve25519.KeyAgreement.PrivateKey
        public var publicKey: PublicKey {
            PublicKey(mlkemEK: mlkem.publicKey.rawRepresentation,
                      x25519PK: x25519.publicKey.rawRepresentation)
        }
    }

    public struct Encapsulation {
        public let mlkemCT: Data
        public let x25519EphPK: Data
        public let shared: Data         // sender-side; never transmitted
    }

    public static func generateKeypair() -> Keypair {
        // MLKEM768.PrivateKey() throws in the shipping SDK; random keygen only
        // fails catastrophically, so try! keeps the non-throwing API contract.
        Keypair(mlkem: try! MLKEM768.PrivateKey(), x25519: Curve25519.KeyAgreement.PrivateKey())
    }

    private static func combine(ssMLKEM: Data, ssX: Data, mlkemCT: Data, xEphPK: Data, recipientXPK: Data) -> Data {
        // X-Wing-style: fold both shared secrets PLUS the full transcript —
        // INCLUDING the ML-KEM ciphertext — so the derived key is bound to this
        // exact exchange (ciphertext transcript-binding). MUST match kem.py's
        // 5-element order [ss_mlkem, ss_x, mlkem_ct, x_eph_pk, recipient_x_pk] or
        // phone<->Mac shared secrets diverge and the tunnel never opens.
        Primitives.hkdfCombine([ssMLKEM, ssX, mlkemCT, xEphPK, recipientXPK], info: Params.labelXWing, length: 32)
    }

    public static func encapsulate(to recipient: PublicKey) throws -> Encapsulation {
        // ML-KEM encapsulation against the recipient's EK.
        let ek = try MLKEM768.PublicKey(rawRepresentation: recipient.mlkemEK)
        let result = try ek.encapsulate()              // -> (sharedSecret, encapsulated)
        let ssMLKEM = result.sharedSecret.withUnsafeBytes { Data($0) }

        // Ephemeral X25519 DH against the recipient's X25519 public key.
        let eph = Curve25519.KeyAgreement.PrivateKey()
        let recipientX = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipient.x25519PK)
        let ssX = try eph.sharedSecretFromKeyAgreement(with: recipientX).withUnsafeBytes { Data($0) }

        let shared = combine(ssMLKEM: ssMLKEM, ssX: ssX, mlkemCT: result.encapsulated,
                             xEphPK: eph.publicKey.rawRepresentation, recipientXPK: recipient.x25519PK)
        return Encapsulation(mlkemCT: result.encapsulated,
                             x25519EphPK: eph.publicKey.rawRepresentation, shared: shared)
    }

    public static func decapsulate(_ kp: Keypair, mlkemCT: Data, x25519EphPK: Data) throws -> Data {
        let ssMLKEM = try kp.mlkem.decapsulate(mlkemCT).withUnsafeBytes { Data($0) }
        let ephPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: x25519EphPK)
        let ssX = try kp.x25519.sharedSecretFromKeyAgreement(with: ephPub).withUnsafeBytes { Data($0) }
        return combine(ssMLKEM: ssMLKEM, ssX: ssX, mlkemCT: mlkemCT,
                       xEphPK: x25519EphPK, recipientXPK: kp.x25519.publicKey.rawRepresentation)
    }
}
