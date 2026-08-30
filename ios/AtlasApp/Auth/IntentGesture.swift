import Foundation
import LocalAuthentication

/// The intent gesture — Atlas's stand-in for Apple Pay's "double-click the side button
/// to confirm". The literal side button is PassKit-only (Apple reserves it for Apple
/// Pay), so for a general high-stakes action we use the one deliberate,
/// Secure-Enclave-attested confirmation iOS actually hands a third-party app: a
/// per-ACTION Face ID / Touch ID evaluation whose prompt names the exact action.
///
/// This is the identity-independent "yes, do THIS, now" — distinct from ambient/ring
/// liveness (which answers who / alive). It is precisely what the (suspended) YubiKey
/// fingerprint modelled: a physical, unspoofable, per-action human confirmation. No
/// confirm → the action does not proceed (fail-closed).
///
/// HONEST BOUNDARY: Face ID here is the *gesture*, gated by the Secure Enclave. To make
/// the step-up *signature itself* require the gesture (so a bare boolean can't stand in),
/// promote the signer to a biometry-gated `SecureEnclave.P256.Signing` key — see
/// HANDOFF_HARDWARE.md §2. That needs a P-256 step-up parity path in AtlasCore + a
/// compiled swift-test run, so it is a follow-up, not this app-layer wiring.
enum IntentGesture {
    enum Failure: LocalizedError {
        case cancelled
        case biometryUnavailable
        case failed(String)

        var errorDescription: String? {
            switch self {
            case .cancelled: return "confirmation cancelled"
            case .biometryUnavailable: return "Face ID / Touch ID unavailable"
            case .failed(let m): return m
            }
        }
    }

    /// Ask the live human to confirm ONE specific action. Returns `true` only on a
    /// successful biometric confirm; throws (fail-closed) on cancel, lockout, or no
    /// enrolled biometry. `action` is shown verbatim in the system prompt, so pass a
    /// human sentence that names the exact thing being authorized.
    @discardableResult
    static func confirm(action: String) async throws -> Bool {
        let ctx = LAContext()
        ctx.localizedCancelTitle = "Cancel"

        // A high-stakes intent gesture demands BIOMETRY (a deliberate face/touch), not a
        // passcode typed from memory — so we evaluate biometrics only and fail closed if
        // none are enrolled, rather than silently downgrading to the device passcode.
        var probe: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &probe) else {
            throw Failure.biometryUnavailable
        }
        do {
            let ok = try await ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                                  localizedReason: action)
            guard ok else { throw Failure.cancelled }
            return true
        } catch let e as LAError {
            switch e.code {
            case .userCancel, .systemCancel, .appCancel, .userFallback:
                throw Failure.cancelled
            default:
                throw Failure.failed(e.localizedDescription)
            }
        }
    }
}
