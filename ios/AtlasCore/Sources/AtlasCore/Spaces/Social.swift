import Foundation

/// Social reactions over Space content — votes (like/dislike, Reddit-style) and reports (flag
/// for moderation). Mirrors `backend/atlas/spaces/social.py` byte-for-byte. Not new crypto:
/// HybridSign signatures over domain-separated, length-prefixed bodies.
///
/// ONE-HUMAN-ONE-VOTE: a vote carries a `nullifier` — an opaque, per-target, per-HUMAN tag
/// (cf. space-pseudonym nullifiers) — and `tally` dedupes by it (LAST cast wins), so a single
/// human can't inflate a score from many pseudonyms yet can change their own vote. The
/// nullifier is caller-supplied here (the interface is the contract); the personhood/PoLE
/// layer makes it unforgeable + unlinkable across targets.
public enum Social {
    public enum SocialError: Error, Equatable { case badVoteValue }

    fileprivate static let voteDomain = Data("atlas/social/vote/v1".utf8)
    fileprivate static let reportDomain = Data("atlas/social/report/v1".utf8)

    public static let like = 1
    public static let dislike = -1

    /// Length-prefix (4-byte big-endian) — matches Python `_lp`.
    fileprivate static func lp(_ b: Data) -> Data {
        var n = UInt32(b.count).bigEndian
        return withUnsafeBytes(of: &n) { Data($0) } + b
    }
    fileprivate static func u64(_ v: UInt64) -> Data {
        var n = v.bigEndian; return withUnsafeBytes(of: &n) { Data($0) }
    }

    // MARK: - votes (like / dislike)

    public struct Vote {
        public var voter: HybridSign.PublicKey
        public var target: Data              // a content hash
        public var value: Int                // +1 like or -1 dislike
        public var nullifier: Data           // per-target, per-human dedupe key
        public var epoch: UInt64
        public var sig: Data = Data()

        public init(voter: HybridSign.PublicKey, target: Data, value: Int,
                    nullifier: Data, epoch: UInt64, sig: Data = Data()) {
            self.voter = voter; self.target = target; self.value = value
            self.nullifier = nullifier; self.epoch = epoch; self.sig = sig
        }

        func body() -> Data {
            voteDomain + lp(voter.encode()) + lp(target)
                + Data([value >= 0 ? 0x01 : 0xff]) + lp(nullifier) + u64(epoch)
        }
    }

    public static func castVote(_ kp: HybridSign.Keypair, target: Data, value: Int,
                                nullifier: Data, epoch: UInt64) throws -> Vote {
        guard value == like || value == dislike else { throw SocialError.badVoteValue }
        var v = Vote(voter: kp.publicKey, target: target, value: value, nullifier: nullifier, epoch: epoch)
        v.sig = try HybridSign.sign(kp, v.body())
        return v
    }

    /// App-facing: a persona casts a like/dislike on a target. The voting keypair and a
    /// per-(persona, target) nullifier are derived INSIDE the module (the persona's secret never
    /// leaves), so one persona is exactly one last-wins vote per target. Cross-persona votes are
    /// distinct voters (person-level one-vote is the person-nullifier work, separate).
    public static func castVote(by profile: Profile, target: Data, up: Bool, epoch: UInt64) throws -> Vote {
        let voter = try profile.feature("vote")
        let nullifier = Primitives.hkdf(ikm: voter.handle,
                                        info: Data("atlas/vote/nullifier".utf8) + target, length: 32)
        return try castVote(voter.keypair, target: target, value: up ? like : dislike,
                            nullifier: nullifier, epoch: epoch)
    }

    public static func verifyVote(_ v: Vote) -> Bool {
        (v.value == like || v.value == dislike) && HybridSign.verify(v.voter, v.body(), v.sig)
    }

    public struct Score: Equatable {
        public let target: Data
        public let likes: Int
        public let dislikes: Int
        public var net: Int { likes - dislikes }
    }

    /// Reddit-style score. Only VALID votes for THIS target count; one-human-one-vote via
    /// nullifier dedup (LAST cast wins, so re-voting flips like↔dislike instead of stacking).
    public static func tally(target: Data, votes: [Vote]) -> Score {
        var latest: [Data: Vote] = [:]
        for v in votes where v.target == target && verifyVote(v) {
            latest[v.nullifier] = v                  // last valid vote per human wins
        }
        let likes = latest.values.filter { $0.value == like }.count
        let dislikes = latest.values.filter { $0.value == dislike }.count
        return Score(target: target, likes: likes, dislikes: dislikes)
    }

    // MARK: - reports (flag for moderators)

    public struct Report {
        public var reporter: HybridSign.PublicKey
        public var target: Data
        public var reason: String            // short code, e.g. "spam" / "harm" / "abuse"
        public var epoch: UInt64
        public var sig: Data = Data()

        public init(reporter: HybridSign.PublicKey, target: Data, reason: String,
                    epoch: UInt64, sig: Data = Data()) {
            self.reporter = reporter; self.target = target; self.reason = reason
            self.epoch = epoch; self.sig = sig
        }

        func body() -> Data {
            reportDomain + lp(reporter.encode()) + lp(target)
                + lp(Data(reason.utf8)) + u64(epoch)
        }
    }

    public static func fileReport(_ kp: HybridSign.Keypair, target: Data, reason: String,
                                  epoch: UInt64) throws -> Report {
        var r = Report(reporter: kp.publicKey, target: target, reason: reason, epoch: epoch)
        r.sig = try HybridSign.sign(kp, r.body())
        return r
    }

    public static func verifyReport(_ r: Report) -> Bool {
        HybridSign.verify(r.reporter, r.body(), r.sig)
    }

    /// Distinct-reporter counts per target (a moderator queue signal). Dedupes multiple reports
    /// from the same reporter on the same target so one persona can't manufacture a pile-on.
    public static func reportCounts(_ reports: [Report]) -> [Data: Int] {
        var seen: [Data: Set<Data>] = [:]
        for r in reports where verifyReport(r) {
            seen[r.target, default: []].insert(r.reporter.encode())
        }
        return seen.mapValues { $0.count }
    }
}
