import Foundation
import CryptoKit
import LocalAuthentication
import AtlasCore

/// Enclave-side arming minter (Payment spec §4 step 2–3, §5). SOURCE ONLY.
///
/// Gates arming on the Atlas verified-human check: a current liveness
/// attestation (ring + Enclave) AND a deliberate side-button intent press, then
/// signs the arming with a Secure-Enclave-held key. The Enclave holds NO card
/// key; the card holds only this Enclave public key.
///
/// Side button (§5): use the platform-sanctioned mechanism. `LAContext`
/// evaluating `.deviceOwnerAuthenticationWithBiometrics` surfaces the Face ID /
/// side-button confirmation; for payments, Apple's side-button double-press
/// (PassKit) is the sanctioned path. Implement the press as a GATE, never a key
/// store (§5). For high-value actions, optionally require ring co-motion
/// correlation (reuses the enrolment ring-lock).
@MainActor
public final class ArmingMinter {
    private let store: SecureEnclaveStore
    public init(store: SecureEnclaveStore) { self.store = store }

    public enum MintError: Error { case noLiveness, intentDeclined, coMotionRequired, enclave(Error) }

    /// Returns the arming signature bytes, or throws if the gate fails. The
    /// `liveness` attestation comes from the Atlas liveness subsystem; `intent`
    /// is resolved by the OS side-button/biometric confirmation.
    public func mintArming(descriptor: TransactionDescriptor, cardID: Data, cardNonce: Data,
                           liveness: LivenessAttestation?, requireCoMotion: Bool,
                           coMotionConfirmed: Bool) async throws -> Data {
        guard let l = liveness, l.verify(), l.operate else { throw MintError.noLiveness }
        if requireCoMotion && !coMotionConfirmed { throw MintError.coMotionRequired }

        // Deliberate human-intent press (the YubiKey-touch replacement, §5).
        let ctx = LAContext()
        ctx.localizedReason = "Confirm payment of \(descriptor.amount) to \(descriptor.recipientID)"
        let pressed: Bool = await withCheckedContinuation { cont in
            ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                               localizedReason: ctx.localizedReason ?? "Authorize payment") { ok, _ in
                cont.resume(returning: ok)
            }
        }
        guard pressed else { throw MintError.intentDeclined }

        // Sign the arming with the Secure-Enclave key (private half never leaves).
        let message = armingMessage(descriptor, cardID: cardID, cardNonce: cardNonce)
        do {
            let key = try store.loadOrCreateEnclaveSigningKey()
            // NOTE: Card 2 verifies classical Ed25519 in the prototype (spec §7.3);
            // the Enclave P-256 signature here must match what the applet verifies.
            // Align the applet's verify curve with this key (P-256) OR mint with a
            // dedicated Ed25519 arming key — a §8 review checkpoint.
            let sig = try key.signature(for: message)
            return sig.rawRepresentation
        } catch { throw MintError.enclave(error) }
    }
}
