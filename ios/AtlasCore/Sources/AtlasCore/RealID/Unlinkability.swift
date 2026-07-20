import Foundation

/// Per-epoch pseudonym rotation + DP, and the behavioural duress channel
/// (Real-ID spec §6/§7; closes T-20 and T-7). Mirrors
/// `backend/atlas/realid/pseudonym.py` and `duress.py`. The heavier
/// verification-inheritance / non-custody pieces are backend-tested; their Swift
/// port follows the same interfaces.
///
/// IMPORTANT (same discipline as the backend): the verification-INHERITANCE
/// proof is a BBS+ anonymous credential. Do NOT reimplement BBS+ in Swift
/// (Step-Zero rule). Pseudonym rotation + duress below need no pairing crypto and
/// are pure-Swift; only the inheritance proof needs BBS+.
///
/// VETTED iOS PATH (identified 2026-07; the binding itself is UNVERIFIED until a
/// Mac/Xcode build — treat as "path identified", not "done"):
///   * There is NO mature pure-Swift BBS+. The vetted engines are Rust over
///     BLS12-381 (trinsic-id/bbs reference impl; MATTR's Ursa-lineage `bbs`
///     crate), tracking IETF draft-irtf-cfrg-bbs-signatures-10 (Jan 2026).
///   * The Rust core is proven to run natively on iOS: animo/react-native-bbs-
///     signatures ships it via CocoaPods native deps (FFI-wrapped
///     mattrglobal/ffi-bbs-signatures). Bind that SAME native lib DIRECTLY from
///     Swift via its C FFI (SwiftPM binary target), not through React Native.
///   * Wire it to the anti-transplant helpers ALREADY in the Swift port
///     (`Provenance.livenessBindLabel` / `inheritedBindLabel` / `captureBinding`)
///     by putting the capture-binding value in the BBS `presentation_header` —
///     that nonce/domain binding IS the accountable-attribution mechanism. So
///     this is FFI plumbing, NOT research and NOT a hand-roll.
///   * THREAT-MODEL CAVEAT: BBS+ unforgeability is CLASSICAL (discrete log over
///     BLS12-381), NOT post-quantum, while the rest of the stack is PQC-hybrid
///     (ML-KEM). The proofs' PRIVACY/unlinkability survives a quantum adversary;
///     the signature's UNFORGEABILITY does not. Logged in THREAT_COVERAGE.md
///     (T-25b) as an accepted asymmetry (no mature PQC BBS+ equivalent exists).
///   * DESIGN REQUIREMENT to make the quantum-forgery containment REAL (verified
///     from the Python source that it is NOT yet enforced there either): the
///     "verified-human" verdict must NOT rest on the BBS proof alone. Bind a
///     PRESENCE-GATED LK into attribution validity via a WITNESSABLE-BUT-SECRET
///     commitment — provable against a public anchor without exposing the private
///     LK (a plain input-bind breaks recipient verifiability; the LK is network-
///     private). Then a forged BBS proof alone is insufficient: the forger must
///     also be live+present holding the current LK. Contains remote/harvest
///     forgery; NOT a present insider (LK is cohort-shared). Carry this into the
///     BBS+ wiring here AND back-fill it in the Python provenance construction.

// MARK: Per-epoch pseudonyms (T-20)

public enum Unlinkability {
    /// epoch_pseudonym = Derive(child secret, drand_round): fresh per epoch,
    /// unlinkable across epochs, stable within one; one-way (no child/System-ID
    /// recovery). The same child still roots to the same System-ID for
    /// accountability.
    public static func epochPseudonym(childSecret: Data, drandRound: Data) -> Data {
        Primitives.H(Data("atlas/epoch-pseudonym".utf8), childSecret, drandRound)
    }
}

/// Differential-privacy-treated observable (Laplace noise) so per-epoch
/// side-channel counts/timing don't correlate. ε is the privacy parameter.
public struct DPCounter {
    public let epsilon: Double
    public let sensitivity: Double
    public init(epsilon: Double = 0.5, sensitivity: Double = 1.0) {
        self.epsilon = epsilon; self.sensitivity = sensitivity
    }
    public func release(trueCount: Int, u: Double) -> Double {
        // u in (-0.5, 0.5); Laplace via inverse CDF. b = sensitivity/epsilon.
        let b = sensitivity / epsilon
        let noise = -b * (u < 0 ? -1.0 : 1.0) * log(1 - 2 * abs(u))
        return Double(trueCount) + noise
    }
}

// MARK: Behavioural duress channel (T-7)

public struct DuressEnrolment {
    let salt: Data
    let normalHash: Data
    let duressHash: Data
    let canaryFinger: Int

    public static func enrol(normalPattern: Data, duressPattern: Data, canaryFinger: Int) -> DuressEnrolment {
        let salt = Primitives.randomBytes(16)
        return DuressEnrolment(
            salt: salt,
            normalHash: Primitives.H(Data("atlas/duress".utf8), salt, normalPattern),
            duressHash: Primitives.H(Data("atlas/duress".utf8), salt, duressPattern),
            canaryFinger: canaryFinger)
    }
    func matches(_ pattern: Data, _ which: Data) -> Bool {
        // constant-time compare
        let h = Primitives.H(Data("atlas/duress".utf8), salt, pattern)
        guard h.count == which.count else { return false }
        var diff: UInt8 = 0
        for (a, b) in zip(h, which) { diff |= a ^ b }
        return diff == 0
    }
}

public struct AuthOutcome {
    public let surfaceSuccess: Bool        // what an observer sees (identical both paths)
    public let duress: Bool                // internal only
    public let sensitiveActionAllowed: Bool
}

public func authenticate(_ enr: DuressEnrolment, pattern: Data, finger: Int,
                         sensitive: Bool = true) -> AuthOutcome {
    let isNormal = enr.matches(pattern, enr.normalHash)
    let isDuress = enr.matches(pattern, enr.duressHash)
    let isCanary = (finger == enr.canaryFinger)
    if !(isNormal || isDuress) {
        return AuthOutcome(surfaceSuccess: false, duress: false, sensitiveActionAllowed: false)
    }
    let duress = isDuress || isCanary
    return AuthOutcome(surfaceSuccess: true, duress: duress,
                       sensitiveActionAllowed: sensitive ? !duress : true)
}
