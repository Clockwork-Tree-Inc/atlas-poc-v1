import Foundation

/// Presence-conditioned epoch-key unwrap (Locked Model §2.3, FIX #7). Mirrors
/// `backend/atlas/session/presence.py`.
///
/// Ratcheting is STRUCTURALLY gated on live enrolled presence — not a separable
/// "if present" check, but by making the epoch key itself unusable without
/// presence:
///
///     enrolled-live-user + continuously-present
///         -> Secure-Enclave releases the enrollment secret
///         -> unwrap the current epoch key
///         -> access the current LK
///         -> ratchet.
///
/// The epoch key is delivered WRAPPED. Unwrapping requires the enrollment
/// secret, which the device's Secure Enclave releases ONLY on a live biometric
/// match while PoLE is operating. No presence -> no release -> the AEAD unwrap
/// MATHEMATICALLY fails -> no epoch key -> no LK -> no ratchet, by construction.
public enum Presence {
    // EXACT byte strings (must match presence.py).
    static let enrollLabel = Data("atlas/epoch-enroll".utf8)   // _ENROLL_LABEL
    static let unwrapAAD = Data("atlas/epoch-key".utf8)        // _UNWRAP_AAD
    static let lkAAD = Data("atlas/lk".utf8)                   // _LK_AAD

    private static func unwrapKey(_ enrollmentSecret: Data, drandRound: Data) -> Data {
        Primitives.hkdf(ikm: enrollmentSecret, info: Data("atlas/epoch-unwrap|".utf8) + drandRound, length: 32)
    }

    /// Server side: wrap the epoch key to the device's enrollment secret so only a
    /// present, enrolled device can unwrap it (no-epoch-key -> no-unwrap).
    public static func wrapEpochKey(_ epochKey: Data, enrollmentSecret: Data, drandRound: Data) throws -> Data {
        try Primitives.aeadEncrypt(key: unwrapKey(enrollmentSecret, drandRound: drandRound), plaintext: epochKey, aad: unwrapAAD)
    }

    /// Device side: unwrap using the enclave-RELEASED presence secret. Throws if
    /// the secret is wrong/absent (i.e. not the enrolled, present device).
    public static func unwrapEpochKey(_ wrapped: Data, presenceSecret: Data, drandRound: Data) throws -> Data {
        try Primitives.aeadDecrypt(key: unwrapKey(presenceSecret, drandRound: drandRound), blob: wrapped, aad: unwrapAAD)
    }

    // --- epoch key WRAPS the LK (§2.5 / FIX #15) ---------------------------
    // The SECRET, presence-gated epoch key (a global cloud value derived from population-
    // scale timing + best-available RNG — NOT the public drand beacon) is what unlocks the
    // private LK. drand is only the public timekeeper (epoch id + attestation), never this
    // key. Dependency chain: continuity=yes -> unwrap epoch key (presence) -> unlock LK ->
    // derive session key. Wrapping the LK under a PUBLIC value would void its secrecy.

    private static func lkKey(_ epochKey: Data, drandRound: Data) -> Data {
        Primitives.hkdf(ikm: epochKey, info: Data("atlas/lk-unlock|".utf8) + drandRound, length: 32)
    }

    /// Wrap the private LK UNDER the secret, presence-gated epoch key. Only a present,
    /// enrolled party who can unwrap the epoch key can then unlock the LK.
    public static func wrapLK(_ lk: Data, epochKey: Data, drandRound: Data) throws -> Data {
        try Primitives.aeadEncrypt(key: lkKey(epochKey, drandRound: drandRound), plaintext: lk, aad: lkAAD)
    }

    /// Unlock the LK with the (unwrapped) epoch key. Throws if the epoch key is
    /// wrong — no epoch key -> no LK.
    public static func unlockLK(_ wrappedLK: Data, epochKey: Data, drandRound: Data) throws -> Data {
        try Primitives.aeadDecrypt(key: lkKey(epochKey, drandRound: drandRound), blob: wrappedLK, aad: lkAAD)
    }
}

/// The device-side enrollment binding: the enrollment secret sealed in the
/// Secure Enclave, released ONLY on live enrolled presence. Mirrors
/// `presence.EnrolledPresence`.
public final class EnrolledPresence {
    private let sealed: Data
    private let enclave: BiometricEnclave

    public init(_ enrollmentSecret: Data, enclave: BiometricEnclave, biometric: Data) {
        // presence.py enrols only when the enclave has no template yet; the Swift
        // `BiometricEnclave` protocol exposes no `hasBiometric`, but Device always
        // injects a FRESH enclave, so an unconditional enrol is equivalent here.
        enclave.enrolBiometric(biometric)
        self.sealed = enclave.seal(enrollmentSecret, label: Presence.enrollLabel)
        self.enclave = enclave
    }

    /// Release the enrollment secret iff the user is CONTINUOUSLY PRESENT: PoLE
    /// operating (continuity intact) AND a live biometric match inside the
    /// enclave. Returns nil otherwise -> the caller cannot unwrap the epoch key.
    public func release(liveBiometric: Data, pole: PoLEState) -> Data? {
        guard pole.operate else { return nil }   // continuity broken -> no release
        return enclave.release(sealed, liveSample: liveBiometric, label: Presence.enrollLabel)
    }
}
