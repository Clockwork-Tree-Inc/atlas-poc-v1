import Foundation

/// Encrypted vault at rest + the PQC layering rule (§4.1). Mirrors
/// `backend/atlas/session/vault.py`.
///
/// AES-256-GCM under the storage-context key; encrypted at rest continuously.
/// PQC is spent ONLY at public-key moments (wrapping a key to a recipient) via
/// ML-KEM+X25519 — never double-encrypting data bytes.
public final class Vault {
    private let storageKey: Data
    private var store: [String: Data] = [:]
    public init(storageKey: Data) {
        precondition(storageKey.count == 32)
        self.storageKey = storageKey
    }

    public func put(_ name: String, _ plaintext: Data) throws {
        store[name] = try Primitives.aeadEncrypt(key: storageKey, plaintext: plaintext, aad: Data(name.utf8))
    }
    public func get(_ name: String) throws -> Data {
        try Primitives.aeadDecrypt(key: storageKey, blob: store[name]!, aad: Data(name.utf8))
    }
    /// Ciphertext as stored — what an attacker with disk access sees. After a
    /// suspicious wipe the key is gone but this stays an unreadable brick (§5.4).
    public func rawAtRest(_ name: String) -> Data? { store[name] }
    public func contains(_ name: String) -> Bool { store[name] != nil }

    // PQC is spent only here: wrap a key to a recipient (§4.1).
    public static func wrapKey(to recipient: HybridKEM.PublicKey, key: Data) throws -> [String: Data] {
        let enc = try HybridKEM.encapsulate(to: recipient)
        let wrapped = try Primitives.aeadEncrypt(key: enc.shared, plaintext: key, aad: Data("atlas/key-wrap".utf8))
        return ["mlkemCT": enc.mlkemCT, "x25519EphPK": enc.x25519EphPK, "wrapped": wrapped]
    }
    public static func unwrapKey(_ kp: HybridKEM.Keypair, bundle: [String: Data]) throws -> Data {
        let shared = try HybridKEM.decapsulate(kp, mlkemCT: bundle["mlkemCT"]!, x25519EphPK: bundle["x25519EphPK"]!)
        return try Primitives.aeadDecrypt(key: shared, blob: bundle["wrapped"]!, aad: Data("atlas/key-wrap".utf8))
    }
}
