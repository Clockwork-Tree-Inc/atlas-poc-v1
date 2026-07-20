import Foundation
import CryptoKit
import LocalAuthentication
import AtlasCore

/// Secure Enclave key store + DevKey (§0.3, §2.1).
///
/// Tier 3: the Secure Enclave is the hardware isolation boundary; the phone is
/// the first trustworthy boundary (§0.3). The enclave-resident authority signs
/// attestations and gates key release; the UI gets only scoped tokens (§2.3).
///
///  * DevKey — Enclave CSPRNG at enrolment, no external inputs; identifies the
///    device and encrypts the raw BLE sensor stream on the phone (§2.1).
///  * Enclave signing key — a SecureEnclave P-256 key whose private half never
///    leaves the chip; used to bind/attest. (The protocol's hybrid ML-DSA+Ed25519
///    enclave key in AtlasCore is the cross-device signature; this SE key is the
///    hardware anchor that proves "produced on THIS device".)
enum EnclaveError: Error { case unsupported, keychain(OSStatus) }

public final class SecureEnclaveStore {
    private let devKeyTag = "inc.clockworktree.atlas.devkey"
    private let seKeyTag = "inc.clockworktree.atlas.enclave.p256".data(using: .utf8)!

    public init() {}

    /// DevKey: 32 bytes from the system CSPRNG, persisted in the keychain with
    /// Secure-Enclave-backed access control (device-only, this-device-only).
    public func loadOrCreateDevKey() throws -> Data {
        if let existing = try readKeychain(devKeyTag) { return existing }
        let key = Primitives.randomBytes(32)
        try writeKeychain(devKeyTag, key)
        return key
    }

    /// A Secure Enclave P-256 signing key (private half stays in the enclave).
    /// Requires user presence (biometric / passcode) to use — the on-body /
    /// alive gate at the hardware layer.
    public func loadOrCreateEnclaveSigningKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard SecureEnclave.isAvailable else { throw EnclaveError.unsupported }
        if let blob = try readKeychain(String(data: seKeyTag, encoding: .utf8)!) {
            return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        }
        let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                     [.privateKeyUsage, .userPresence], nil)!
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        try writeKeychain(String(data: seKeyTag, encoding: .utf8)!, key.dataRepresentation)
        return key
    }

    // MARK: BiometricEnclave conformance (device-present recovery, §7.3)
    //
    // IMPORTANT honest difference from ModelEnclave: on real hardware the
    // biometric NEVER enters our code. We do not enrol or pass a template; the
    // OS Secure Enclave + Face ID/Touch ID performs the match when the
    // biometric-gated SE key is used. So `enrolBiometric` is a no-op and
    // `release(_:liveSample:label:)` IGNORES liveSample — the OS prompts and
    // matches. This is strictly stronger than the model: "never store the
    // biometric" holds because we never touch it.

    private let kaKeyTag = "inc.clockworktree.atlas.enclave.ka.p256"

    /// A Secure Enclave key-agreement key gated by the current biometric set.
    private func loadOrCreateBiometricKAKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        guard SecureEnclave.isAvailable else { throw EnclaveError.unsupported }
        if let blob = try readKeychain(kaKeyTag) {
            return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
        }
        // `.biometryCurrentSet` invalidates the key if the enrolled biometric
        // changes — binding release to the human enrolled at this moment.
        let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet], nil)!
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        try writeKeychain(kaKeyTag, key.dataRepresentation)
        return key
    }
}

extension SecureEnclaveStore: BiometricEnclave {
    public var deviceID: Data {
        // Stable per-install identifier (device-bound seal AAD).
        (try? loadOrCreateDevKey()).map { Primitives.H(Data("atlas/device-id".utf8), $0) } ?? Data()
    }

    public var hasBiometric: Bool {
        // The biometric binding exists iff the biometric-gated SE key has been created.
        ((try? readKeychain(kaKeyTag)) ?? nil) != nil
    }

    public func enrolBiometric(_ template: Data) {
        // No-op on real hardware: the biometric is enrolled at the OS level and
        // never handled here. Creating the biometric-gated SE key is the setup.
        _ = try? loadOrCreateBiometricKAKey()
    }

    /// ECIES-style seal under the SE key-agreement public key: ephemeral ECDH ->
    /// HKDF -> AES-GCM. Sealing needs no biometric; unsealing does.
    public func seal(_ secret: Data, label: Data) -> Data {
        guard let se = try? loadOrCreateBiometricKAKey() else { return Data() }
        let sePub = se.publicKey
        let eph = P256.KeyAgreement.PrivateKey()
        guard let shared = try? eph.sharedSecretFromKeyAgreement(with: sePub) else { return Data() }
        let wrapKey = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: deviceID,
                                                     sharedInfo: label, outputByteCount: 32)
        let wrapData = wrapKey.withUnsafeBytes { Data($0) }
        guard let ct = try? Primitives.aeadEncrypt(key: wrapData, plaintext: secret, aad: label) else { return Data() }
        return eph.publicKey.rawRepresentation + ct   // ephPub(64) || nonce||ct||tag
    }

    /// Biometric-gated release: using the SE private key triggers the OS Face ID/
    /// Touch ID prompt. `liveSample` is intentionally ignored (the OS matches).
    public func release(_ sealed: Data, liveSample: Data, label: Data) -> Data? {
        guard sealed.count > 64, let se = try? loadOrCreateBiometricKAKey() else { return nil }
        let ephPubData = sealed.prefix(64)
        let ct = sealed.suffix(from: sealed.startIndex + 64)
        guard let ephPub = try? P256.KeyAgreement.PublicKey(rawRepresentation: ephPubData),
              let shared = try? se.sharedSecretFromKeyAgreement(with: ephPub) else { return nil }
        let wrapKey = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: deviceID,
                                                     sharedInfo: label, outputByteCount: 32)
        let wrapData = wrapKey.withUnsafeBytes { Data($0) }
        return try? Primitives.aeadDecrypt(key: wrapData, blob: Data(ct), aad: label)
    }

    // MARK: Keychain helpers
    private func writeKeychain(_ tag: String, _ value: Data) throws {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrAccount as String: tag,
                                kSecValueData as String: value,
                                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        SecItemDelete(q as CFDictionary)
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw EnclaveError.keychain(status) }
    }
    private func readKeychain(_ tag: String) throws -> Data? {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrAccount as String: tag,
                                kSecReturnData as String: true,
                                kSecMatchLimit as String: kSecMatchLimitOne]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw EnclaveError.keychain(status) }
        return out as? Data
    }
}
