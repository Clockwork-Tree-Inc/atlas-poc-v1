import Foundation

/// PoLE receipts wallet — portable, identity-free proofs that genuine LIVE ENTROPY was sampled during
/// a window (PoLE = Proof of Living Entropy: unpredictable, unreproducible signal from the real
/// environment — a living body is a dense source, but so is the ambient world; not anthropocentric).
/// Byte-for-byte parity with `backend/atlas/economy/presence_receipt.py`. A receipt carries
/// one or more signers (persona + optional independent co-signers — wearable, Secure Enclave); it
/// attests presence over [start,end] committing to fused evidence (`poleCommit`) without raw signals.
/// `verifyReceipt(minSigners: 2)` enforces multi-stream corroboration.
public enum PresenceReceiptNS {

    static let label = Data("atlas/presence-receipt/v1".utf8)
    static let idLabel = Data("atlas/presence-receipt-id".utf8)

    static func lp(_ d: Data) -> Data { var n = UInt32(d.count).bigEndian; return withUnsafeBytes(of: &n) { Data($0) } + d }
    static func u32(_ v: Int) -> Data { var n = UInt32(v).bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }
    static func be8(_ v: Int) -> Data { var n = UInt64(v).bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }

    public struct PresenceReceipt: Equatable {
        public let subject: Data
        public let windowStart: Int
        public let windowEnd: Int
        public let poleCommit: Data
        public let signers: [HybridSign.PublicKey]
        public let sigs: [Data]

        public init(subject: Data, windowStart: Int, windowEnd: Int, poleCommit: Data,
                    signers: [HybridSign.PublicKey], sigs: [Data]) {
            self.subject = subject; self.windowStart = windowStart; self.windowEnd = windowEnd
            self.poleCommit = poleCommit; self.signers = signers; self.sigs = sigs
        }

        public func body() -> Data {
            let encs = signers.map { $0.encode() }.sorted { $0.lexicographicallyPrecedes($1) }
            var buf = label + lp(subject) + be8(windowStart) + be8(windowEnd) + lp(poleCommit) + u32(encs.count)
            for e in encs { buf += lp(e) }
            return buf
        }
        public func id() -> Data { Primitives.H(idLabel, body()) }
        public func covers(at: Int) -> Bool { windowStart <= at && at <= windowEnd }
    }

    public static func mintReceipt(signers: [HybridSign.Keypair], subject: Data, windowStart: Int,
                                   windowEnd: Int, poleCommit: Data) throws -> PresenceReceipt {
        precondition(windowEnd >= windowStart, "window_end < window_start")
        let pubs = signers.map { $0.publicKey }
        let tmp = PresenceReceipt(subject: subject, windowStart: windowStart, windowEnd: windowEnd,
                                  poleCommit: poleCommit, signers: pubs, sigs: [])
        let body = tmp.body()
        let sigs = try signers.map { try HybridSign.sign($0, body) }
        return PresenceReceipt(subject: subject, windowStart: windowStart, windowEnd: windowEnd,
                               poleCommit: poleCommit, signers: pubs, sigs: sigs)
    }

    public static func verifyReceipt(_ r: PresenceReceipt, minSigners: Int = 1) -> Bool {
        guard r.signers.count == r.sigs.count, !r.signers.isEmpty else { return false }
        let body = r.body()
        var seen: Set<Data> = []
        for (pub, sig) in zip(r.signers, r.sigs) {
            let enc = pub.encode()
            if !seen.contains(enc), HybridSign.verify(pub, body, sig) { seen.insert(enc) }
        }
        return seen.count >= minSigners
    }

    /// A persona's collection of presence receipts — the PoLE receipts wallet.
    public final class ReceiptWallet {
        private var receiptsByID: [Data: PresenceReceipt] = [:]
        public init() {}

        @discardableResult
        public func add(_ r: PresenceReceipt, minSigners: Int = 1) -> Bool {
            guard verifyReceipt(r, minSigners: minSigners) else { return false }
            receiptsByID[r.id()] = r
            return true
        }
        public var receipts: [PresenceReceipt] { Array(receiptsByID.values) }
        public func covering(at: Int, minSigners: Int = 1) -> [PresenceReceipt] {
            receiptsByID.values.filter { $0.covers(at: at) && verifyReceipt($0, minSigners: minSigners) }
        }
        public func totalPresence() -> Int {
            receiptsByID.values.reduce(0) { $0 + max(0, $1.windowEnd - $1.windowStart) }
        }
    }
}
