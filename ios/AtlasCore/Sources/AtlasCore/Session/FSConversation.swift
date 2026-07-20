import Foundation

/// Forward-secret two-party conversation chain. Mirrors
/// `backend/atlas/session/fs_conversation.py` byte-for-byte on the crypto core.
///
/// Each message is sealed under a per-message key drawn from a delete-as-you-go
/// chain, seeded from the live co-derived session/LK material both parties share.
/// The chain advances ONE-WAY (HKDF), so a leaked message/chain key reveals
/// neither past nor future message keys. It is deterministic, so both sides
/// ratchet in lockstep with NO per-message secret transmitted. Separate chains
/// per direction (A->B, B->A), Signal-style. The blind node only relays ciphertext.
///
/// "Static keys for who-you-are, session keys for what-you-say": content is
/// sealed under the RATCHETED key, seeded from the STATIC KEM channel key AND the
/// live co-derived LK — never a static key alone.
public enum FSConversation {
    static let chainInfo = Data("atlas/fs-conv/chain".utf8)

    /// Both parties derive the SAME seed for a given direction from shared live
    /// material: static KEM channel key + live co-derived LK + epoch. `direction`
    /// (e.g. "A->B") makes the two directions independent chains.
    public static func seedChain(channelKey: Data, lk: Data, drandRound: Data, direction: Data) -> Data {
        Primitives.hkdfCombine([channelKey, lk, drandRound, direction], info: chainInfo, length: 32)
    }

    /// One-way step -> (messageKey, nextChainKey). The caller uses messageKey once
    /// and discards the old chainKey; neither is recoverable from what follows.
    static func step(_ chainKey: Data, beaconT: Data, drandRound: Data) -> (mk: Data, ck: Data) {
        let mk = Primitives.hkdfCombine([chainKey, Data("mk".utf8), beaconT, drandRound], info: chainInfo, length: 32)
        let ck = Primitives.hkdfCombine([chainKey, Data("ck".utf8), beaconT, drandRound], info: chainInfo, length: 32)
        return (mk, ck)
    }
}

/// One direction of the conversation. `seal`/`open` advance the same one-way chain
/// in lockstep; each message key is used exactly once, then gone.
public final class FSChain {
    private var ck: Data
    private let drandRound: Data

    public init(seed: Data, drandRound: Data) {
        self.ck = seed
        self.drandRound = drandRound
    }

    public func seal(_ plaintext: Data, beaconT: Data, aad: Data = Data()) throws -> Data {
        let (mk, next) = FSConversation.step(ck, beaconT: beaconT, drandRound: drandRound)
        ck = next                                     // advance; old chain key discarded
        return try Primitives.aeadEncrypt(key: mk, plaintext: plaintext, aad: aad)
    }

    public func open(_ blob: Data, beaconT: Data, aad: Data = Data()) throws -> Data {
        let (mk, next) = FSConversation.step(ck, beaconT: beaconT, drandRound: drandRound)
        ck = next
        return try Primitives.aeadDecrypt(key: mk, blob: blob, aad: aad)
    }
}
