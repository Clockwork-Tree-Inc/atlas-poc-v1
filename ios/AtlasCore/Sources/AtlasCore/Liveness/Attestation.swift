import Foundation

/// Ratchet-paced liveness attestation + removal states (§5.3, §5.4). Mirrors
/// `backend/atlas/liveness/attestation.py`.
///
/// A continuity-sensing subsystem emits a fresh SIGNED attestation each ratchet
/// step, independent of the key path. At Tier 3 the phone's enclave signature
/// stands in for the absent ring_SE_sig (§5.2) — here a hybrid ML-DSA+Ed25519
/// signature (production: a Secure Enclave-bound key; see AtlasApp/Enclave).
public enum RemovalState: String { case active, voluntary, suspicious }

public struct LivenessAttestation {
    public let drandRound: Data
    public let poleDigest: Data
    public let operate: Bool
    public let enclavePublic: HybridSign.PublicKey
    public let signature: Data
    /// `challenge` binds a verifier-supplied freshness nonce into the signature
    /// (anti-replay, §9.2). A captured/static attestation carries the wrong
    /// (old/empty) challenge and is rejected.
    public let challenge: Data

    public init(drandRound: Data, poleDigest: Data, operate: Bool,
                enclavePublic: HybridSign.PublicKey, signature: Data, challenge: Data = Data()) {
        self.drandRound = drandRound
        self.poleDigest = poleDigest
        self.operate = operate
        self.enclavePublic = enclavePublic
        self.signature = signature
        self.challenge = challenge
    }

    /// SECURITY: length-prefix every field (4-byte big-endian) so the signed
    /// message is an INJECTIVE function of (drandRound, poleDigest, operate,
    /// challenge). A plain `|`-delimited concatenation is ambiguous — a 0x7c
    /// byte inside drandRound (raw beacon randomness) is an alternative split point,
    /// letting one signature re-parse to a different drandRound/challenge. Mirrors
    /// `hkdfCombine`'s length-prefixing discipline and Python's `message_for`:
    /// `b"".join(len(p).to_bytes(4,"big") + p for p in parts)`.
    static func messageFor(drandRound: Data, poleDigest: Data, operate: Bool, challenge: Data = Data()) -> Data {
        let flag = Data([operate ? 0x01 : 0x00])
        let parts: [Data] = [Data("atlas/attest".utf8), drandRound, poleDigest, flag, challenge]
        var out = Data()
        for p in parts {
            var n = UInt32(p.count).bigEndian
            withUnsafeBytes(of: &n) { out.append(contentsOf: $0) }
            out.append(p)
        }
        return out
    }
    public func verify() -> Bool {
        HybridSign.verify(enclavePublic,
                          Self.messageFor(drandRound: drandRound, poleDigest: poleDigest, operate: operate, challenge: challenge),
                          signature)
    }
}

public final class AttestationSubsystem {
    public let enclaveKey: HybridSign.Keypair
    public private(set) var state: RemovalState = .active
    private var onWipe: (() -> Void)?

    public init(enclaveKey: HybridSign.Keypair = HybridSign.generate()) { self.enclaveKey = enclaveKey }
    public func setOnWipe(_ cb: @escaping () -> Void) { onWipe = cb }

    public var contributesPresence: Bool { state == .active }
    /// Corrected model (§2.3 / FIX #13): EVERY end path is inert at rest. Only
    /// ACTIVE ratchets — voluntary/proper-end and suspicious both stop.
    public var ratchets: Bool { state == .active }

    /// Emit a signed attestation for this ratchet step, if still attesting.
    /// A non-operating PoLE (P(L|S) < pi*) is a liveness break -> suspicious.
    /// `challenge` is a fresh verifier nonce signed into the attestation so a
    /// relying party can demand proof of liveness *now* (anti-replay, §9.2).
    public func attest(_ pole: PoLEState, challenge: Data = Data()) -> LivenessAttestation? {
        if state == .suspicious { return nil }
        guard pole.operate else { markSuspicious(); return nil }
        let msg = LivenessAttestation.messageFor(drandRound: pole.drandRound, poleDigest: pole.stateDigest,
                                                 operate: true, challenge: challenge)
        let sig = (try? HybridSign.sign(enclaveKey, msg)) ?? Data()
        return LivenessAttestation(drandRound: pole.drandRound, poleDigest: pole.stateDigest, operate: true,
                                   enclavePublic: enclaveKey.publicKey, signature: sig, challenge: challenge)
    }

    /// Voluntary / proper session-end: go INERT at rest (FIX #13). Like every
    /// other end path it stops ratcheting AND wipes RAM key material. Differs from
    /// suspicious ONLY in the reconnection discriminator (a coherent re-bind is
    /// benign, no full recovery). Fail-closed, never fail-stale.
    public func removeVoluntary() {
        if state == .suspicious { return }
        state = .voluntary
        onWipe?()
    }
    public func markSuspicious() { state = .suspicious; onWipe?() }

    /// Reconnection discriminator (§5.4).
    @discardableResult
    public func reconnect(trajectoryCoherent: Bool) -> RemovalState {
        if trajectoryCoherent {
            if state == .voluntary { state = .active }   // light re-bind
            return state
        }
        markSuspicious(); return state
    }
}
