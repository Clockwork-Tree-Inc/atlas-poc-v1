import Foundation

/// Local duress slice — panic-code decoy + zeroize-on-suspicion.
/// Mirrors `backend/atlas/session/duress_vault.py`.
///
/// Two composable mechanisms on the existing fail-closed `Vault`:
///  1. PANIC CODE -> DECOY, real stays sealed. A normal passcode unwraps the real
///     storage key; a panic passcode unwraps only a DECOY key. Surface-identical;
///     the panic-derived key CANNOT unseal the real key (different KDF key).
///  2. ZEROIZE-ON-SUSPICION. Destroys the real key -> the real vault is a
///     permanent brick (no path back to plaintext); the decoy stays alive.
///
/// HONEST BOUNDARY: on device the real storage-key seal is the **Secure Enclave**
/// (biometry-gated, non-extractable), not this AES model; hardware anti-tamper
/// zeroize + true hidden-volume decoy plausibility are out of scope.
public enum DuressError: Error, Equatable {
    case codesMustDiffer
    case zeroized
}

public struct UnlockResult {
    public let surfaceOK: Bool     // identical for normal vs panic
    public let duress: Bool        // internal only, never surfaced
    public let vault: Vault?       // real view (normal) or decoy view (panic)
}

public final class PanicVault {
    private static let codeInfo = Data("atlas/duress/code-key".utf8)
    private static let sealAADReal = Data("atlas/duress/seal|real".utf8)
    private static let sealAADDecoy = Data("atlas/duress/seal|decoy".utf8)

    private let salt: Data
    private var realKey: Data?
    private var sealedReal: Data?
    private let sealedDecoy: Data
    private var realVault: Vault?
    private let decoyVault: Vault
    private var zeroizedFlag = false
    private let onZeroize: ((String) -> Void)?

    private static func codeKey(_ code: Data, _ salt: Data) -> Data {
        Primitives.hkdf(ikm: code, info: codeInfo, salt: salt, length: 32)
    }

    public init(normalCode: Data, panicCode: Data,
                onZeroize: ((String) -> Void)? = nil) throws {
        if Primitives.H(Data("atlas/duress/code".utf8), normalCode)
            == Primitives.H(Data("atlas/duress/code".utf8), panicCode) {
            throw DuressError.codesMustDiffer
        }
        let salt = Primitives.randomBytes(16)
        let realKey = Primitives.randomBytes(32)
        let decoyKey = Primitives.randomBytes(32)
        self.salt = salt
        self.realKey = realKey
        self.sealedReal = try Primitives.aeadEncrypt(
            key: PanicVault.codeKey(normalCode, salt), plaintext: realKey, aad: PanicVault.sealAADReal)
        self.sealedDecoy = try Primitives.aeadEncrypt(
            key: PanicVault.codeKey(panicCode, salt), plaintext: decoyKey, aad: PanicVault.sealAADDecoy)
        self.realVault = Vault(storageKey: realKey)
        self.decoyVault = Vault(storageKey: decoyKey)
        self.onZeroize = onZeroize
    }

    public func putReal(_ name: String, _ plaintext: Data) throws {
        guard !zeroizedFlag, let v = realVault else { throw DuressError.zeroized }
        try v.put(name, plaintext)
    }

    public func seedDecoy(_ name: String, _ plaintext: Data) throws {
        try decoyVault.put(name, plaintext)
    }

    /// Try the code against the real seal, then the decoy seal. Normal -> real
    /// view; panic -> decoy view (duress, internal-only); neither -> surface
    /// failure. Response shape is identical for real vs panic.
    public func unlock(_ code: Data) -> UnlockResult {
        if !zeroizedFlag, let sealed = sealedReal,
           (try? Primitives.aeadDecrypt(key: PanicVault.codeKey(code, salt), blob: sealed,
                                        aad: PanicVault.sealAADReal)) != nil {
            return UnlockResult(surfaceOK: true, duress: false, vault: realVault)
        }
        if (try? Primitives.aeadDecrypt(key: PanicVault.codeKey(code, salt), blob: sealedDecoy,
                                        aad: PanicVault.sealAADDecoy)) != nil {
            return UnlockResult(surfaceOK: true, duress: true, vault: decoyVault)
        }
        return UnlockResult(surfaceOK: false, duress: false, vault: nil)
    }

    /// Destroy the real key material. Real vault entries stay as unreadable
    /// bricks; no path back to plaintext. Idempotent. Decoy remains openable.
    public func zeroizeOnSuspicion(_ reason: String = "suspicion") {
        realKey = nil
        sealedReal = nil
        realVault = nil
        zeroizedFlag = true
        onZeroize?(reason)
    }

    public var zeroized: Bool { zeroizedFlag }
}
