import Foundation
import CommonCrypto

/// Threshold recovery — STRATIFIED by release mechanism (§7.2, §7.3). Mirrors
/// `backend/atlas/keys/recovery.py`.
///
///   * DEVICE-PRESENT (card, in-person, normal auth) -> Secure Enclave robust
///     biometric release of `share_bio` (device-bound).
///   * TOTAL-LOSS / catastrophic -> the two PORTABLE shares (card + context),
///     NO Enclave and NO biometric. Fuzzy extractor RETIRED (TRUST_LAYER.md #7):
///     the anti-spoof at total loss is the in-person recovery person.
///
/// Invariants: never store the biometric (Enclave-sealed only); 2-of-3 threshold
/// unchanged; total-loss never depends on a single device's Enclave (no Enclave param).
public enum RecoveryError: Error { case attestationRequired, enclaveReleaseFailed,
                                        noTrustedContext, unknownHandle, badPasscode(remaining: Int),
                                        attemptsExhausted,
                                        /// Holder-authority gate (§6): recovery is triggered ONLY by the
                                        /// user's own authority — no operator, court, or system path. Same
                                        /// discipline as rerooting's OperatorForbidden.
                                        holderAuthorityRequired }

/// Passcode KDF: salted + stretched. The recovery-child passcode is a low-entropy
/// selector (the real secrecy is biometric + threshold), but it must still resist
/// offline brute force if the enrolment record leaks — so never store a bare hash.
private let passcodeIters: UInt32 = 100_000

/// PBKDF2-HMAC-SHA256 (matches Python `hashlib.pbkdf2_hmac("sha256", ..., 100_000)`,
/// default 32-byte output). CryptoKit has no PBKDF2, so use CommonCrypto.
private func derivePasscode(_ passcode: String, salt: Data) -> Data {
    let pwd = Data(passcode.utf8)
    var derived = Data(count: 32)
    let status = derived.withUnsafeMutableBytes { (dk: UnsafeMutableRawBufferPointer) -> Int32 in
        salt.withUnsafeBytes { (saltPtr: UnsafeRawBufferPointer) -> Int32 in
            pwd.withUnsafeBytes { (pwdPtr: UnsafeRawBufferPointer) -> Int32 in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    pwdPtr.bindMemory(to: Int8.self).baseAddress, pwd.count,
                    saltPtr.bindMemory(to: UInt8.self).baseAddress, salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    passcodeIters,
                    dk.bindMemory(to: UInt8.self).baseAddress, 32)
            }
        }
    }
    precondition(status == kCCSuccess, "PBKDF2 derivation failed")
    return derived
}

/// Constant-time byte compare (mirrors Python `hmac.compare_digest`).
private func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for (x, y) in zip(a, b) { diff |= x ^ y }
    return diff == 0
}

/// Artifacts produced once, at enrolment (§7.2). Reference type: the lockout
/// counter is PERSISTED HERE (not on the gate object) so re-instantiating the
/// gate does NOT reset the 3-attempt limit.
public final class RecoveryEnrolment {
    public let shareCard: Shamir.Share          // portable; JavaCard
    public let shareContext: Shamir.Share       // portable; trusted-context vertex
    public let enclaveDeviceID: Data            // device-present release (Enclave)
    public let enclaveSealedBio: Data
    public let recoveryChildHandle: Data
    let passcodeSalt: Data
    let passcodeHash: Data
    // Lockout counter lives HERE (the persisted record), not on the gate object —
    // otherwise an attacker resets the limit by re-instantiating the gate.
    var childAttemptsRemaining: Int = 3

    init(shareCard: Shamir.Share, shareContext: Shamir.Share, enclaveDeviceID: Data,
         enclaveSealedBio: Data, recoveryChildHandle: Data, passcodeSalt: Data, passcodeHash: Data) {
        self.shareCard = shareCard; self.shareContext = shareContext
        self.enclaveDeviceID = enclaveDeviceID; self.enclaveSealedBio = enclaveSealedBio
        self.recoveryChildHandle = recoveryChildHandle
        self.passcodeSalt = passcodeSalt; self.passcodeHash = passcodeHash
    }
}

public enum Recovery {
    static let bioLabel = Data("share-bio".utf8)

    public static func enrol(_ tree: IdentityTree, biometricTemplate: Data,
                             device: BiometricEnclave, passcode: String,
                             sphincs: SphincsProvider) throws -> RecoveryEnrolment {
        let shares = Shamir.split(tree.tskSeed, n: 3, k: 2)
        let shareBio = shares[1]
        // Device-present: enrol biometric + seal share_bio to this device.
        device.enrolBiometric(biometricTemplate)
        let enclaveSealed = device.seal(shareBio.encode(), label: bioLabel)
        let salt = Primitives.randomBytes(16)
        return RecoveryEnrolment(
            shareCard: shares[0], shareContext: shares[2],
            enclaveDeviceID: device.deviceID, enclaveSealedBio: enclaveSealed,
            recoveryChildHandle: tree.child(.recovery).handle,
            passcodeSalt: salt,
            passcodeHash: derivePasscode(passcode, salt: salt))
    }

    // MARK: Device-present — Secure Enclave robust biometric release

    private static func enclaveBioShare(_ enr: RecoveryEnrolment, _ device: BiometricEnclave,
                                        _ liveSample: Data) -> Shamir.Share? {
        guard device.deviceID == enr.enclaveDeviceID else { return nil }  // device-bound
        guard let raw = device.release(enr.enclaveSealedBio, liveSample: liveSample, label: bioLabel)
        else { return nil }
        return Shamir.Share.decode(raw)
    }

    public static func recoverViaCard(_ enr: RecoveryEnrolment, device: BiometricEnclave,
                                      cardShare: Shamir.Share, liveBiometric: Data, attested: Bool,
                                      userAuthorized: Bool, sphincs: SphincsProvider) throws -> IdentityTree {
        guard userAuthorized else { throw RecoveryError.holderAuthorityRequired }
        guard attested else { throw RecoveryError.attestationRequired }
        guard let bio = enclaveBioShare(enr, device, liveBiometric) else { throw RecoveryError.enclaveReleaseFailed }
        return try IdentityTree.build(tskSeed: Shamir.combine([cardShare, bio]), sphincs: sphincs)
    }

    public static func recoverInPerson(_ enr: RecoveryEnrolment, device: BiometricEnclave,
                                       liveBiometric: Data, attested: Bool, inPersonTrustedContext: Bool,
                                       userAuthorized: Bool, sphincs: SphincsProvider) throws -> IdentityTree {
        guard userAuthorized else { throw RecoveryError.holderAuthorityRequired }
        guard attested else { throw RecoveryError.attestationRequired }
        guard inPersonTrustedContext else { throw RecoveryError.noTrustedContext }
        guard let bio = enclaveBioShare(enr, device, liveBiometric) else { throw RecoveryError.enclaveReleaseFailed }
        return try IdentityTree.build(tskSeed: Shamir.combine([bio, enr.shareContext]), sphincs: sphincs)
    }

    /// Normal auth: robust device-present human-proof (no secret leaves).
    public static func releaseForAuth(_ enr: RecoveryEnrolment, device: BiometricEnclave,
                                      liveBiometric: Data) -> Bool {
        enclaveBioShare(enr, device, liveBiometric) != nil
    }

    // MARK: Total-loss — the two PORTABLE threshold shares (NO Enclave, NO biometric)

    /// Recovery from TOTAL DEVICE LOSS on a NEW device: combine the card share (Half B, which
    /// you carry) and the trusted-context vertex (released only under the in-person recovery
    /// ceremony) into 2-of-3. NO Enclave and NO biometric — the anti-spoof is the live,
    /// accountable recovery person of the in-person ceremony (see recovery_anchor).
    public static func recoverTotalLoss(_ enr: RecoveryEnrolment, cardShare: Shamir.Share,
                                        contextShare: Shamir.Share, attested: Bool,
                                        inPersonTrustedContext: Bool,
                                        userAuthorized: Bool, sphincs: SphincsProvider) throws -> IdentityTree {
        guard userAuthorized else { throw RecoveryError.holderAuthorityRequired }
        guard attested else { throw RecoveryError.attestationRequired }
        guard inPersonTrustedContext else { throw RecoveryError.noTrustedContext }
        return try IdentityTree.build(tskSeed: Shamir.combine([cardShare, contextShare]),
                                      sphincs: sphincs)
    }
}

/// Private handle + 3-attempt passcode -> recovery child capability only (§7.3).
///
/// The attempt counter is PERSISTED in the enrolment record (`enr`), not on this
/// object — so re-instantiating the gate does NOT reset the lockout (that bypass
/// would otherwise turn the 3-attempt limit into unlimited guesses). A correct
/// passcode does not consume an attempt; only failures do.
public final class RecoveryChildGate {
    private let enr: RecoveryEnrolment
    public init(_ enr: RecoveryEnrolment) { self.enr = enr }

    public var attemptsRemaining: Int { enr.childAttemptsRemaining }

    public func attempt(assertedHandle: Data, passcode: String, attested: Bool,
                        userAuthorized: Bool = true) throws -> Data {
        guard userAuthorized else { throw RecoveryError.holderAuthorityRequired }
        guard attested else { throw RecoveryError.attestationRequired }
        guard enr.childAttemptsRemaining > 0 else { throw RecoveryError.attemptsExhausted }
        guard assertedHandle == enr.recoveryChildHandle else {
            enr.childAttemptsRemaining -= 1
            throw RecoveryError.unknownHandle
        }
        let candidate = derivePasscode(passcode, salt: enr.passcodeSalt)
        guard constantTimeEquals(candidate, enr.passcodeHash) else {
            enr.childAttemptsRemaining -= 1
            throw RecoveryError.badPasscode(remaining: enr.childAttemptsRemaining)
        }
        return enr.recoveryChildHandle
    }
}
