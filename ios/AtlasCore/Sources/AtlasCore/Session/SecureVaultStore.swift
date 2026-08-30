import Foundation

/// On-phone secure vault (C9). Mirrors `backend/atlas/session/secure_vault.py`.
///
/// Drop anything in; it is sealed to a storage key that lives sealed in the
/// non-exportable Secure Enclave, released ONLY on live presence (biometric +
/// PoLE operating), and each item carries a provenance stamp binding it to the
/// author + content + time.
///
/// BACKUP is a per-vault CHOICE:
///  * `.phoneOnly`   — safest; the key never leaves the Enclave (lose phone = lose content).
///  * `.nonCustodial` — the storage key is KEM-wrapped to the user's RECOVERY key
///    and shipped as an opaque blob; the host cannot read it, only recovery restores.
///
/// HONEST BOUNDARY: cryptographic UNREADABILITY (content encrypted to a key even
/// Apple can't extract, presence-gated) — NOT physical exclusion of Apple from the
/// device. Claim "even Apple can't read it," not "Apple can't reach the storage."
/// On device the seal is the REAL Secure Enclave (`AtlasApp/Enclave`); this core
/// uses the `ModelEnclave` seal so the logic is testable off-device.
public enum BackupChoice: String, Sendable { case phoneOnly = "phone_only", nonCustodial = "noncustodial" }

public enum VaultError: Error { case notPresent(String), backupNotEnabled, provenanceMismatch }

public struct VaultStamp: Sendable {
    public let authorHandle: Data
    public let contentHash: Data
    public let epochRound: Data
    public let signature: Data

    public func core() -> Data {
        Primitives.H(Data("atlas/vault-stamp".utf8), authorHandle, contentHash, epochRound)
    }
    public func verify(authorPublic: HybridSign.PublicKey) -> Bool {
        HybridSign.verify(authorPublic, core(), signature)
    }
}

public struct VaultItem: Sendable {
    public let ciphertext: Data
    public let stamp: VaultStamp
}

public final class SecureVaultStore {
    private static let vaultLabel = Data("atlas/secure-vault/storage-key".utf8)
    private static let itemAAD = Data("atlas/secure-vault/item".utf8)
    private static let backupLabel = Data("atlas/secure-vault/backup".utf8)

    private let enclave: BiometricEnclave
    private let author: Child
    private let backup: BackupChoice
    private let sealedStorage: Data              // storage key sealed in the Enclave
    private var store: [String: VaultItem] = [:]

    public init(enclave: BiometricEnclave = ModelEnclave(), biometric: Data, author: Child,
                backup: BackupChoice = .phoneOnly) {
        // Only enrol on a FRESH enclave (mirrors Python secure_vault: `if not
        // enclave.has_biometric`). Re-enrolling over an existing binding would re-point
        // every already-sealed secret to a new biometric — a shared/reused enclave must
        // not have its template silently overwritten by constructing a second vault.
        if !enclave.hasBiometric { enclave.enrolBiometric(biometric) }
        self.enclave = enclave
        self.author = author
        self.backup = backup
        let storageKey = Primitives.randomBytes(32)
        self.sealedStorage = enclave.seal(storageKey, label: SecureVaultStore.vaultLabel)
        // storageKey goes out of scope here — never retained in the clear.
    }

    // -- at-rest persistence ("ciphertext anywhere") --------------------------
    //
    // Everything in the export is ALREADY at rest: the enclave-sealed storage key + the item
    // ciphertexts/stamps. Persisting it to disk and reloading gives a vault that survives app
    // relaunches; reading any item still requires the enclave (biometric) + live PoLE.

    /// The whole vault at rest: sealed storage key + item ciphertexts. Safe to persist as-is.
    public func atRestExport() -> Data {
        var items: [String: [String: String]] = [:]
        for (name, it) in store {
            items[name] = ["ct": it.ciphertext.base64EncodedString(),
                           "author": it.stamp.authorHandle.base64EncodedString(),
                           "hash": it.stamp.contentHash.base64EncodedString(),
                           "round": it.stamp.epochRound.base64EncodedString(),
                           "sig": it.stamp.signature.base64EncodedString()]
        }
        let obj: [String: Any] = ["v": 1, "sealedStorage": sealedStorage.base64EncodedString(),
                                  "items": items]
        return (try? JSONSerialization.data(withJSONObject: obj)) ?? Data()
    }

    /// Reopen a persisted vault: same sealed storage key, same items. Fails (returns nil) on a
    /// malformed blob — the caller falls back to a fresh vault.
    public init?(restoringFrom data: Data, enclave: BiometricEnclave = ModelEnclave(),
                 biometric: Data, author: Child, backup: BackupChoice = .phoneOnly) {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let sealedB64 = obj["sealedStorage"] as? String,
              let sealed = Data(base64Encoded: sealedB64),
              let items = obj["items"] as? [String: [String: String]]
        else { return nil }
        if !enclave.hasBiometric { enclave.enrolBiometric(biometric) }
        self.enclave = enclave
        self.author = author
        self.backup = backup
        self.sealedStorage = sealed
        for (name, f) in items {
            guard let ct = f["ct"].flatMap({ Data(base64Encoded: $0) }),
                  let ah = f["author"].flatMap({ Data(base64Encoded: $0) }),
                  let hash = f["hash"].flatMap({ Data(base64Encoded: $0) }),
                  let round = f["round"].flatMap({ Data(base64Encoded: $0) }),
                  let sig = f["sig"].flatMap({ Data(base64Encoded: $0) }) else { continue }
            store[name] = VaultItem(ciphertext: ct,
                                    stamp: VaultStamp(authorHandle: ah, contentHash: hash,
                                                      epochRound: round, signature: sig))
        }
    }

    public var backupChoice: BackupChoice { backup }

    private func release(liveBiometric: Data, pole: PoLEState) throws -> Data {
        guard pole.operate else { throw VaultError.notPresent("PoLE not operating") }
        guard let key = enclave.release(sealedStorage, liveSample: liveBiometric,
                                        label: SecureVaultStore.vaultLabel) else {
            throw VaultError.notPresent("biometric did not match on this device")
        }
        return key
    }

    public func put(_ name: String, _ data: Data, liveBiometric: Data, pole: PoLEState,
                    beacon: BeaconRound) throws {
        let key = try release(liveBiometric: liveBiometric, pole: pole)
        let contentHash = Primitives.H(Data("atlas/vault-content".utf8), data)
        let core = Primitives.H(Data("atlas/vault-stamp".utf8), author.handle, contentHash, beacon.epochRound())
        let stamp = VaultStamp(authorHandle: author.handle, contentHash: contentHash,
                               epochRound: beacon.epochRound(), signature: try HybridSign.sign(author.keypair, core))
        let ct = try Primitives.aeadEncrypt(key: key, plaintext: data,
                                            aad: SecureVaultStore.itemAAD + Data(name.utf8))
        store[name] = VaultItem(ciphertext: ct, stamp: stamp)
    }

    public func get(_ name: String, liveBiometric: Data, pole: PoLEState) throws -> Data {
        let key = try release(liveBiometric: liveBiometric, pole: pole)
        guard let item = store[name] else { throw VaultError.provenanceMismatch }
        let data = try Primitives.aeadDecrypt(key: key, blob: item.ciphertext,
                                              aad: SecureVaultStore.itemAAD + Data(name.utf8))
        guard item.stamp.contentHash == Primitives.H(Data("atlas/vault-content".utf8), data),
              item.stamp.verify(authorPublic: author.publicKey) else {
            throw VaultError.provenanceMismatch
        }
        return data
    }

    public func rawAtRest(_ name: String) -> Data? { store[name]?.ciphertext }

    /// Names of every item at rest (ciphertext only — no plaintext released). Lets the
    /// app enumerate the vault for a file browser without unlocking anything.
    public var names: [String] { Array(store.keys) }

    /// Whether an item is stored (no unlock needed).
    public func contains(_ name: String) -> Bool { store[name] != nil }

    /// Remove an item's ciphertext at rest. Deletion needs no biometric (you're
    /// destroying, not reading) but only affects THIS device's store.
    @discardableResult
    public func delete(_ name: String) -> Bool { store.removeValue(forKey: name) != nil }

    // -- backup CHOICE ------------------------------------------------------

    public func exportBackup(recoveryPub: HybridKEM.PublicKey, liveBiometric: Data,
                             pole: PoLEState) throws -> [String: Any] {
        guard backup == .nonCustodial else { throw VaultError.backupNotEnabled }
        let key = try release(liveBiometric: liveBiometric, pole: pole)
        let enc = try HybridKEM.encapsulate(to: recoveryPub)
        let sealedKey = try Primitives.aeadEncrypt(key: enc.shared, plaintext: key,
                                                   aad: SecureVaultStore.backupLabel)
        return ["mlkemCT": enc.mlkemCT, "x25519EphPK": enc.x25519EphPK, "sealedKey": sealedKey,
                "items": store]
    }

    public static func restoreBackup(mlkemCT: Data, x25519EphPK: Data, sealedKey: Data,
                                     recoveryKP: HybridKEM.Keypair, name: String, itemCT: Data) throws -> Data {
        let shared = try HybridKEM.decapsulate(recoveryKP, mlkemCT: mlkemCT, x25519EphPK: x25519EphPK)
        let storageKey = try Primitives.aeadDecrypt(key: shared, blob: sealedKey, aad: backupLabel)
        return try Primitives.aeadDecrypt(key: storageKey, blob: itemCT, aad: itemAAD + Data(name.utf8))
    }
}
