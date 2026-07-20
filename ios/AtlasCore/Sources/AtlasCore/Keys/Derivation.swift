import Foundation

/// Session key derivation, forward-secret ratchet, contexts and tokens
/// (§2.2, §2.3). Mirrors `backend/atlas/keys/derivation.py` + `tokens.py`.
public enum KeyError: Error { case destroyed }

/// RAM-only session key (§2.2). `destroy()` zeroises it — the primary
/// containment mechanism. Reference type so a wipe is observed by all holders.
public final class SessionKey {
    public let drandRound: Data
    private var bytes: [UInt8]
    private(set) public var alive = true
    init(drandRound: Data, key: Data) { self.drandRound = drandRound; self.bytes = Array(key) }

    public var key: Data {
        get throws {
            guard alive else { throw KeyError.destroyed }
            return Data(bytes)
        }
    }
    public func contextKey(_ context: String) throws -> Data {
        let info: Data
        switch context {
        case "storage": info = Params.contextStorage
        case "recognition": info = Params.contextRecognition
        case "tunnel": info = Params.contextTunnel
        default: fatalError("unknown context \(context)")
        }
        return Primitives.hkdfCombine([try key], info: info, length: 32)
    }
    public func destroy() {
        for i in bytes.indices { bytes[i] = 0 }
        alive = false
    }
}

public enum Derivation {
    /// SessKey = HKDF(PoLE_value, LK, epoch_key, prev_key, ctx) (§2.3).
    /// `poleValue` is a physio-timed clean QRNG value (the ring's live signal
    /// timed the firing; the value is clean QRNG). No continuity flag, no raw
    /// physiology, no drand. Input list order preserved for cross-impl parity.
    public static func sessionKeyDecoupled(lk: Data, epochKey: Data, poleValue: Data,
                                           prevKey: Data, contextSeparator: Data,
                                           drandRound: Data) -> SessionKey {
        let m = Primitives.hkdfCombine([lk, epochKey, poleValue, prevKey, contextSeparator],
                                       info: Params.labelSession, length: 32)
        return SessionKey(drandRound: drandRound, key: m)
    }

    /// Claimed embodiment (Math Spec §A); built for parity, not the default.
    public static func sessionKeyCoupled(tsk: Data, devKey: Data, poleState: Data,
                                         beacon: Data, drandRound: Data) -> SessionKey {
        let m = Primitives.hkdfCombine([tsk, devKey, poleState, beacon],
                                       info: Params.labelSession, length: 32)
        return SessionKey(drandRound: drandRound, key: m)
    }

    /// Forward-secret ratchet (§2.2):
    /// K[t+1] = HKDF( K[t] || H(entropy_t) || beacon_t || drand_round ).
    public static func ratchet(_ prevKey: Data, entropyT: Data, beaconT: Data, drandRound: Data) -> Data {
        Primitives.hkdfCombine([prevKey, Primitives.H(entropyT), beaconT, drandRound],
                               info: Params.labelRatchet, length: 32)
    }
}
