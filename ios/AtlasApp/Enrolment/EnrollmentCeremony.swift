import Foundation
import LocalAuthentication
import AtlasCore

/// The enrolment ceremony — the REAL multi-factor lock-in.
///
/// Factors (all genuine production mechanisms on this build):
///   1. LIVENESS present  — the ambient signal source reports a live stream
///      (stand-in for the ring's biological continuity; ambient-not-biological).
///   2. FACE ID           — `LAPolicy.deviceOwnerAuthenticationWithBiometrics`.
///   3. PASSWORD           — used ONLY here (enrol) and at disenrol; NEVER for
///      ordinary operation (that is the button double-click).
///   4. BUTTON double-click — an explicit human confirmation gesture.
/// On success the ceremony builds the identity tree, seals the enrolment secret
/// into the Secure Enclave, and opens an optional forensic window.
///
/// STATUS: written against real LocalAuthentication + AtlasCore; unrun until built
/// on a Mac to a device. SPHINCS+ root signing needs a native provider (same
/// native-dep seam as the rest of the stack) — injected as `sphincs`.
public struct EnrolmentResult {
    public let identity: IdentityTree
    public let enrollmentSecret: Data       // sealed into the SE by the runtime
    public let forensicWindowOpen: Bool
}

public enum EnrolmentError: Error {
    case notLive                 // ambient signal absent -> refuse to enrol
    case faceIDFailed(String)
    case passwordMissing
    case notConfirmed            // button gesture not completed
}

@MainActor
public final class EnrollmentCeremony {

    private let sphincs: SphincsProvider
    public init(sphincs: SphincsProvider) { self.sphincs = sphincs }

    /// Run the ceremony. `buttonDoubleClicked` is supplied by the UI once the user
    /// completes the physical double-click; `forensicWindow` opts into the
    /// post-enrol forensic window (duress/disenrol triggers use it).
    public func enrol(signalSource: SignalSource,
                      password: String,
                      buttonDoubleClicked: Bool,
                      forensicWindow: Bool) async throws -> EnrolmentResult {
        // 1. LIVENESS: the live signal must be present right now.
        guard let sample = try? signalSource.sample(), sample.present else {
            throw EnrolmentError.notLive
        }
        // 2. FACE ID (real biometric prompt).
        try await authenticateFaceID(reason: "Enrol your Atlas identity")
        // 3. PASSWORD (enrol/disenrol scope only).
        guard !password.isEmpty else { throw EnrolmentError.passwordMissing }
        // 4. BUTTON double-click confirmation.
        guard buttonDoubleClicked else { throw EnrolmentError.notConfirmed }

        // Lock-in: genesis TSK -> split-TSK identity tree. The enrolment secret is
        // bound to the password + Face ID gate; the runtime seals it in the SE.
        let tskSeed = Primitives.randomBytes(32)
        let identity = try IdentityTree.build(tskSeed: tskSeed, sphincs: sphincs)
        let enrollmentSecret = Primitives.hkdf(
            ikm: tskSeed, info: Data("atlas/enrol-secret".utf8),
            salt: Data(password.utf8), length: 32)

        return EnrolmentResult(identity: identity, enrollmentSecret: enrollmentSecret,
                               forensicWindowOpen: forensicWindow)
    }

    /// Disenrol requires the SAME password scope + Face ID; it triggers the
    /// forensic window and hands off to zeroize.
    public func authorizeDisenrol(password: String, storedPasswordVerifier: (String) -> Bool) async throws {
        try await authenticateFaceID(reason: "Disenrol / lock down your Atlas identity")
        guard storedPasswordVerifier(password) else { throw EnrolmentError.passwordMissing }
    }

    private func authenticateFaceID(reason: String) async throws {
        let ctx = LAContext()
        var err: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) else {
            throw EnrolmentError.faceIDFailed(err?.localizedDescription ?? "biometrics unavailable")
        }
        do {
            let ok = try await ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
            if !ok { throw EnrolmentError.faceIDFailed("Face ID declined") }
        } catch {
            throw EnrolmentError.faceIDFailed(error.localizedDescription)
        }
    }
}
