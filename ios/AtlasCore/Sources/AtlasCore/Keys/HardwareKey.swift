import Foundation
import CryptoKit

/// YubiKey Bio — the high-stakes hardware factor. Mirrors
/// `backend/atlas/keys/hardware_key.py`.
///
/// High-risk actions (recovery, identity rotation, transfer) are signed by a
/// non-extractable key gated by the YubiKey's OWN on-key fingerprint; the signature
/// binds (action, context, fresh challenge) so it cannot be replayed. Can also hold
/// a recovery Shamir share, released only on the same fingerprint. Fail-closed.
///
/// HONEST BOUNDARY: on device the real key is non-extractable hardware (YubiKit /
/// the YubiKey secure element) and the fingerprint match happens ON the key. This
/// models the protocol with Ed25519 (Curve25519.Signing); `fingerprintMatched`
/// stands in for the on-key biometric gate.
public struct HighStakesRequest {
    public let action: String     // e.g. "recover", "rotate-identity", "transfer"
    public let context: Data      // binds the exact operation
    public let challenge: Data    // fresh verifier nonce (anti-replay)

    public init(action: String, context: Data, challenge: Data) {
        self.action = action; self.context = context; self.challenge = challenge
    }

    public func message() -> Data {
        Primitives.H(Data("atlas/high-stakes".utf8), Data(action.utf8), context, challenge)
    }
}

public enum HardwareKeyError: Error { case fingerprintRequired, refused }

public final class YubiKeyBio {
    private let signing: Curve25519.Signing.PrivateKey      // non-extractable (modeled)
    private var share: Shamir.Share?

    public init() { signing = Curve25519.Signing.PrivateKey() }

    public var publicKey: Data { signing.publicKey.rawRepresentation }

    /// Sign the high-stakes action iff the on-key fingerprint matched.
    public func authorize(_ request: HighStakesRequest, fingerprintMatched: Bool) throws -> Data {
        guard fingerprintMatched else { throw HardwareKeyError.fingerprintRequired }
        return try signing.signature(for: request.message())
    }

    public func holdRecoveryShare(_ s: Shamir.Share) { share = s }

    public func releaseRecoveryShare(fingerprintMatched: Bool) throws -> Shamir.Share {
        guard fingerprintMatched else { throw HardwareKeyError.fingerprintRequired }
        guard let share else { throw HardwareKeyError.refused }
        return share
    }
}

/// Verifier side: the signature must be by THIS key over THIS exact request.
public func verifyHighStakes(_ publicKey: Data, _ request: HighStakesRequest, _ signature: Data) -> Bool {
    guard let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else { return false }
    return pub.isValidSignature(signature, for: request.message())
}
