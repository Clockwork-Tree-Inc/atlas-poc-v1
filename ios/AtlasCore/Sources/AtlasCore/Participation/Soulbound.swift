import Foundation

/// Soul-bound tokens — non-transferable, identity-bound, non-monetary participation credentials.
/// Mirrors `backend/atlas/participation/soulbound.py` byte-for-byte (Python is reference-of-record).
///
/// An SBT is cryptographically bound to a holder's "soul" (their key): it can't be transferred, sold,
/// or reassigned, and carries no value — a proof of participation you COLLECT, not a coin you trade.
public enum Participation {

    static let sbtDomain = Data("atlas/sbt/v1".utf8)
    static let sbtIdLabel = Data("atlas/sbt-id".utf8)
    /// The kind for a PoLE "present, living human this epoch" participation proof.
    public static let participationKind = Data("atlas/sbt/participation".utf8)

    static func lp(_ d: Data) -> Data {
        var n = UInt32(d.count).bigEndian; var o = Data()
        withUnsafeBytes(of: &n) { o.append(contentsOf: $0) }; o.append(d); return o
    }
    static func u64(_ v: Int) -> Data { var n = UInt64(v).bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }

    public struct SoulboundToken {
        public var holder: HybridSign.PublicKey     // the soul this is permanently bound to
        public var kind: Data
        public var issuer: HybridSign.PublicKey     // == holder for self-collected participation
        public var epoch: Int
        public var payload: Data = Data()
        public var sig: Data = Data()

        public init(holder: HybridSign.PublicKey, kind: Data, issuer: HybridSign.PublicKey,
                    epoch: Int, payload: Data = Data(), sig: Data = Data()) {
            self.holder = holder; self.kind = kind; self.issuer = issuer
            self.epoch = epoch; self.payload = payload; self.sig = sig
        }

        func body() -> Data {
            sbtDomain + lp(holder.encode()) + lp(kind) + lp(issuer.encode()) + u64(epoch) + lp(payload)
        }
        public func tokenID() -> Data { Primitives.H(sbtIdLabel, body()) }
    }

    /// Issue a soul-bound token TO `holder` (e.g. an org awarding a badge). The holder is baked into
    /// the signed body, so it can never be transferred to another soul.
    public static func issueSBT(_ issuerKp: HybridSign.Keypair, holder: HybridSign.PublicKey,
                                kind: Data, epoch: Int, payload: Data = Data()) throws -> SoulboundToken {
        var t = SoulboundToken(holder: holder, kind: kind, issuer: issuerKp.publicKey,
                               epoch: epoch, payload: payload)
        t.sig = try HybridSign.sign(issuerKp, t.body())
        return t
    }

    /// Self-collect a PARTICIPATION token for `epoch`, backed by a PoLE commitment. Issuer == holder.
    public static func collectParticipation(_ holderKp: HybridSign.Keypair, epoch: Int,
                                            poleCommitment: Data = Data()) throws -> SoulboundToken {
        try issueSBT(holderKp, holder: holderKp.publicKey, kind: participationKind, epoch: epoch,
                     payload: poleCommitment)
    }

    public static func verifySBT(_ t: SoulboundToken) -> Bool {
        HybridSign.verify(t.issuer, t.body(), t.sig)
    }

    /// A holder's collection. Enforces NON-TRANSFERABILITY: it only holds tokens bound to THIS holder —
    /// you cannot receive, buy, or collect a token soul-bound to someone else. No `transfer` exists.
    public final class SoulboundCollection {
        public let holder: HybridSign.PublicKey
        private var byID: [Data: SoulboundToken] = [:]

        public init(holder: HybridSign.PublicKey) { self.holder = holder }

        @discardableResult
        public func add(_ t: SoulboundToken) -> Bool {
            guard verifySBT(t) else { return false }
            guard t.holder.encode() == holder.encode() else { return false }  // block on transfers
            byID[t.tokenID()] = t
            return true
        }

        public func balance(kind: Data? = nil) -> Int {
            var toks = Array(byID.values)
            if let k = kind { toks = toks.filter { $0.kind == k } }
            var seen = Set<Data>()
            for t in toks { seen.insert(t.kind + Participation.u64(t.epoch)) }
            return seen.count
        }

        public func epochs(kind: Data = Participation.participationKind) -> [Int] {
            Array(Set(byID.values.filter { $0.kind == kind }.map { $0.epoch })).sorted()
        }
    }
}
