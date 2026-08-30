import Foundation

/// Paid attention — stores PAY you to look, instead of stealing your attention. Byte-for-byte parity
/// with `backend/atlas/economy/attention.py`. A reward is paid only to a proven LIVE HUMAN who
/// attended (a valid presence receipt covering the offer window), exactly once per human (a per-offer
/// nullifier). Bots can't farm it: no presence, no pay; one human, one redemption.
public enum Attention {

    public typealias PresenceReceipt = PresenceReceiptNS.PresenceReceipt

    static let offerLabel = Data("atlas/attention-offer/v1".utf8)
    static let offerIDLabel = Data("atlas/attention-offer-id".utf8)
    static let claimLabel = Data("atlas/attention-claim/v1".utf8)
    static let nullLabel = Data("atlas/attention-nullifier/v1".utf8)

    public enum AttentionError: Error, Equatable { case badReward, badWindow, invalidClaim, alreadyRedeemed }

    static func lp(_ d: Data) -> Data { var n = UInt32(d.count).bigEndian; return withUnsafeBytes(of: &n) { Data($0) } + d }
    static func be8(_ v: Int) -> Data { var n = UInt64(v).bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }

    public struct AttentionOffer: Equatable {
        public let store: HybridSign.PublicKey
        public let productID: Data
        public let reward: Int
        public let windowStart: Int
        public let windowEnd: Int
        public var sig: Data

        public init(store: HybridSign.PublicKey, productID: Data, reward: Int,
                    windowStart: Int, windowEnd: Int, sig: Data = Data()) {
            self.store = store; self.productID = productID; self.reward = reward
            self.windowStart = windowStart; self.windowEnd = windowEnd; self.sig = sig
        }
        public func body() -> Data {
            offerLabel + lp(store.encode()) + lp(productID) + be8(reward) + be8(windowStart) + be8(windowEnd)
        }
        public func id() -> Data { Primitives.H(offerIDLabel, body()) }
    }

    public static func makeOffer(_ storeKp: HybridSign.Keypair, productID: Data, reward: Int,
                                 windowStart: Int, windowEnd: Int) throws -> AttentionOffer {
        guard reward > 0 else { throw AttentionError.badReward }
        guard windowEnd >= windowStart else { throw AttentionError.badWindow }
        var o = AttentionOffer(store: storeKp.publicKey, productID: productID, reward: reward,
                               windowStart: windowStart, windowEnd: windowEnd)
        o.sig = try HybridSign.sign(storeKp, o.body())
        return o
    }

    public static func verifyOffer(_ o: AttentionOffer) -> Bool {
        o.reward > 0 && o.windowEnd >= o.windowStart && HybridSign.verify(o.store, o.body(), o.sig)
    }

    public static func attentionNullifier(subject: Data, offerID: Data) -> Data {
        Primitives.H(nullLabel, lp(subject), lp(offerID))
    }

    public struct AttentionClaim: Equatable {
        public let offerID: Data
        public let subject: Data
        public let receipt: PresenceReceipt
        public let nullifier: Data
        public let signer: HybridSign.PublicKey
        public var sig: Data

        public init(offerID: Data, subject: Data, receipt: PresenceReceipt, nullifier: Data,
                    signer: HybridSign.PublicKey, sig: Data = Data()) {
            self.offerID = offerID; self.subject = subject; self.receipt = receipt
            self.nullifier = nullifier; self.signer = signer; self.sig = sig
        }
        public func body() -> Data {
            claimLabel + lp(offerID) + lp(subject) + lp(receipt.id()) + lp(nullifier) + lp(signer.encode())
        }
    }

    public static func claimAttention(_ personaKp: HybridSign.Keypair, offer: AttentionOffer,
                                      receipt: PresenceReceipt) throws -> AttentionClaim {
        var c = AttentionClaim(offerID: offer.id(), subject: receipt.subject, receipt: receipt,
                               nullifier: attentionNullifier(subject: receipt.subject, offerID: offer.id()),
                               signer: personaKp.publicKey)
        c.sig = try HybridSign.sign(personaKp, c.body())
        return c
    }

    static func overlaps(_ r: PresenceReceipt, _ o: AttentionOffer) -> Bool {
        !(r.windowEnd < o.windowStart || r.windowStart > o.windowEnd)
    }

    public static func verifyClaim(_ offer: AttentionOffer, _ claim: AttentionClaim, minSigners: Int = 1) -> Bool {
        guard verifyOffer(offer) else { return false }
        guard claim.offerID == offer.id() else { return false }
        guard claim.receipt.subject == claim.subject else { return false }
        guard PresenceReceiptNS.verifyReceipt(claim.receipt, minSigners: minSigners) else { return false }
        guard overlaps(claim.receipt, offer) else { return false }
        guard claim.nullifier == attentionNullifier(subject: claim.subject, offerID: offer.id()) else { return false }
        let signerEnc = claim.signer.encode()
        guard claim.receipt.signers.contains(where: { $0.encode() == signerEnc }) else { return false }
        return HybridSign.verify(claim.signer, claim.body(), claim.sig)
    }

    /// Pays each valid claim ONCE — the anti-farming gate.
    public final class AttentionLedger {
        private var paid: [Data: Int] = [:]
        public init() {}

        @discardableResult
        public func redeem(_ offer: AttentionOffer, _ claim: AttentionClaim, minSigners: Int = 1) throws -> Int {
            guard verifyClaim(offer, claim, minSigners: minSigners) else { throw AttentionError.invalidClaim }
            guard paid[claim.nullifier] == nil else { throw AttentionError.alreadyRedeemed }
            paid[claim.nullifier] = offer.reward
            return offer.reward
        }
        public func totalPaid() -> Int { paid.values.reduce(0, +) }
    }
}
