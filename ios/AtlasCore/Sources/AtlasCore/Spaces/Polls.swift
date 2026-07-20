import Foundation

/// Polls — Sybil-free polling at configurable anonymity levels. Mirrors `backend/atlas/spaces/polls.py`
/// byte-for-byte (Python is reference-of-record). A poll is a structured multi-option vote; one-human-
/// one-response is enforced by a nullifier, and the IdentityTier controls whether a ballot reveals the
/// voter's persona (anonymous = ephemeral ballot key, unlinkable) — never whether one human can stuff it.
extension Spaces {

    fileprivate static let pollDomain = Data("atlas/poll/v1".utf8)
    fileprivate static let pollResponseDomain = Data("atlas/poll-response/v1".utf8)
    fileprivate static let pollIdLabel = Data("atlas/poll-id".utf8)

    fileprivate static func plp(_ d: Data) -> Data {
        var n = UInt32(d.count).bigEndian; var o = Data()
        withUnsafeBytes(of: &n) { o.append(contentsOf: $0) }; o.append(d); return o
    }
    fileprivate static func pu16(_ v: Int) -> Data { var n = UInt16(v).bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }
    fileprivate static func pu32(_ v: Int) -> Data { var n = UInt32(v).bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }
    fileprivate static func pu64(_ v: Int) -> Data { var n = UInt64(v).bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }

    // IdentityTier is the canonical anonymity axis — declared in SpaceKinds.swift, shared with Spaces.

    public struct Poll {
        public var author: HybridSign.PublicKey
        public var question: Data
        public var options: [Data]
        public var tier: IdentityTier
        public var epoch: Int
        public var sig: Data = Data()

        public init(author: HybridSign.PublicKey, question: Data, options: [Data],
                    tier: IdentityTier, epoch: Int, sig: Data = Data()) {
            self.author = author; self.question = question; self.options = options
            self.tier = tier; self.epoch = epoch; self.sig = sig
        }

        func body() -> Data {
            var out = pollDomain + plp(author.encode()) + plp(question) + pu32(options.count)
            for o in options { out += plp(o) }
            out += pu16(tier.rawValue) + pu64(epoch)
            return out
        }
        public func pollID() -> Data { Primitives.H(pollIdLabel, body()) }
    }

    public static func createPoll(_ kp: HybridSign.Keypair, question: Data, options: [Data],
                                  tier: IdentityTier, epoch: Int) throws -> Poll {
        precondition(options.count >= 2, "a poll needs >= 2 options")
        var p = Poll(author: kp.publicKey, question: question, options: options, tier: tier, epoch: epoch)
        p.sig = try HybridSign.sign(kp, p.body())
        return p
    }

    public static func verifyPoll(_ p: Poll) -> Bool {
        p.options.count >= 2 && HybridSign.verify(p.author, p.body(), p.sig)
    }

    public struct PollResponse {
        public var pollID: Data
        public var choice: Int
        public var nullifier: Data
        public var ballotKey: HybridSign.PublicKey   // voter persona OR ephemeral (anonymous)
        public var epoch: Int
        public var sig: Data = Data()

        public init(pollID: Data, choice: Int, nullifier: Data, ballotKey: HybridSign.PublicKey,
                    epoch: Int, sig: Data = Data()) {
            self.pollID = pollID; self.choice = choice; self.nullifier = nullifier
            self.ballotKey = ballotKey; self.epoch = epoch; self.sig = sig
        }

        func body() -> Data {
            pollResponseDomain + plp(pollID) + pu32(choice) + plp(nullifier)
                + plp(ballotKey.encode()) + pu64(epoch)
        }
    }

    static func makeResponse(_ poll: Poll, _ choice: Int, _ nullifier: Data,
                             _ ballotKey: HybridSign.PublicKey, _ epoch: Int) -> PollResponse {
        precondition(choice >= 0 && choice < poll.options.count, "choice out of range")
        return PollResponse(pollID: poll.pollID(), choice: choice, nullifier: nullifier,
                            ballotKey: ballotKey, epoch: epoch)
    }

    /// PSEUDONYMOUS / VERIFIED_PERSON ballot — signed by the voter's persona (choice visible under nym).
    public static func respond(_ voterKp: HybridSign.Keypair, poll: Poll, choice: Int,
                               nullifier: Data, epoch: Int) throws -> PollResponse {
        var r = makeResponse(poll, choice, nullifier, voterKp.publicKey, epoch)
        r.sig = try HybridSign.sign(voterKp, r.body())
        return r
    }

    /// ANONYMOUS ballot — signed by a fresh ephemeral key, unlinkable to the voter's persona; only the
    /// nullifier enforces one-human-one-response. Eligibility is a ps_credential seam in production.
    public static func respondAnonymously(_ poll: Poll, choice: Int, nullifier: Data, epoch: Int,
                                          ephemeralKp: HybridSign.Keypair) throws -> PollResponse {
        var r = makeResponse(poll, choice, nullifier, ephemeralKp.publicKey, epoch)
        r.sig = try HybridSign.sign(ephemeralKp, r.body())
        return r
    }

    public static func verifyResponse(_ poll: Poll, _ r: PollResponse) -> Bool {
        r.pollID == poll.pollID() && r.choice >= 0 && r.choice < poll.options.count
            && HybridSign.verify(r.ballotKey, r.body(), r.sig)
    }

    public struct PollResult {
        public let pollID: Data
        public let counts: [Int]
        public let total: Int
        public func winner() -> Int {
            guard !counts.isEmpty else { return -1 }
            return counts.indices.max(by: { counts[$0] < counts[$1] })!
        }
    }

    /// One-human-one-response: dedupe by nullifier (LAST valid ballot wins). Only valid responses for
    /// THIS poll count.
    public static func tally(_ poll: Poll, _ responses: [PollResponse]) -> PollResult {
        var latest: [Data: PollResponse] = [:]
        for r in responses where verifyResponse(poll, r) {
            latest[r.nullifier] = r
        }
        var counts = [Int](repeating: 0, count: poll.options.count)
        for r in latest.values { counts[r.choice] += 1 }
        return PollResult(pollID: poll.pollID(), counts: counts, total: latest.count)
    }
}
