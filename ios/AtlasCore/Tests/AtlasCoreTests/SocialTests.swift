import XCTest
@testable import AtlasCore

/// Forum substrate (`Social` — votes / tally / reports), ported from
/// `backend/atlas/spaces/social.py`. Verifies byte-parity of the signed body's field encoding
/// against the Python reference (domain prefix + field suffix; the pubkey middle is already
/// parity-proven via `ProfileTests`), plus sign/verify and the one-human-one-vote tally +
/// distinct-reporter report logic.
final class SocialTests: XCTestCase {

    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
    private func kp(_ tag: UInt8 = 7) throws -> HybridSign.Keypair {
        try HybridSign.keypair(fromSeed: Data((0..<32).map { UInt8(($0 + Int(tag)) % 256) }))
    }

    // Python reference (seed = bytes 0..31): domain prefixes + field suffixes.
    private let voteDomainHex = "61746c61732f736f6369616c2f766f74652f7631"
    private let reportDomainHex = "61746c61732f736f6369616c2f7265706f72742f7631"
    private let likeSuffix = "0000000b7461726765742d68617368010000000b68756d616e2d6e796d2d31000000000000002a"
    private let dislikeSuffix = "0000000b7461726765742d68617368ff0000000b68756d616e2d6e796d2d31000000000000002a"
    private let reportSuffix = "0000000b7461726765742d68617368000000047370616d0000000000000007"

    private let target = Data("target-hash".utf8)
    private let nym = Data("human-nym-1".utf8)

    /// The signed body's field encoding is byte-identical to the Python reference.
    func testVoteAndReportBodyMatchPythonEncoding() throws {
        let k = try HybridSign.keypair(fromSeed: Data((0..<32).map { UInt8($0) }))
        let like = Social.Vote(voter: k.publicKey, target: target, value: Social.like, nullifier: nym, epoch: 42)
        let dislike = Social.Vote(voter: k.publicKey, target: target, value: Social.dislike, nullifier: nym, epoch: 42)
        let report = Social.Report(reporter: k.publicKey, target: target, reason: "spam", epoch: 7)

        XCTAssertTrue(hex(like.body()).hasPrefix(voteDomainHex))
        XCTAssertTrue(hex(like.body()).hasSuffix(likeSuffix), "like body field-encoding must match Python")
        XCTAssertTrue(hex(dislike.body()).hasSuffix(dislikeSuffix), "dislike differs only in the value byte (ff)")
        XCTAssertTrue(hex(report.body()).hasPrefix(reportDomainHex))
        XCTAssertTrue(hex(report.body()).hasSuffix(reportSuffix), "report body field-encoding must match Python")
    }

    func testCastVoteVerifiesAndTamperFails() throws {
        let k = try kp()
        let v = try Social.castVote(k, target: target, value: Social.like, nullifier: nym, epoch: 1)
        XCTAssertTrue(Social.verifyVote(v))
        var flipped = v; flipped.value = Social.dislike           // value not covered by the sig it was made with
        XCTAssertFalse(Social.verifyVote(flipped), "flipping the value must break verification")
        var badSig = v; badSig.sig = Data(v.sig.reversed())
        XCTAssertFalse(Social.verifyVote(badSig))
        XCTAssertThrowsError(try Social.castVote(k, target: target, value: 5, nullifier: nym, epoch: 1))
    }

    /// One-human-one-vote: same nullifier re-voting flips (last cast wins); distinct humans stack.
    func testTallyOneHumanOneVoteLastCastWins() throws {
        let k = try kp()
        let like = try Social.castVote(k, target: target, value: Social.like, nullifier: nym, epoch: 1)
        let flip = try Social.castVote(k, target: target, value: Social.dislike, nullifier: nym, epoch: 2)
        let s1 = Social.tally(target: target, votes: [like, flip])
        XCTAssertEqual(s1, Social.Score(target: target, likes: 0, dislikes: 1))   // last (dislike) wins
        XCTAssertEqual(s1.net, -1)

        let other = try Social.castVote(try kp(9), target: target, value: Social.like,
                                        nullifier: Data("human-nym-2".utf8), epoch: 1)
        let s2 = Social.tally(target: target, votes: [flip, other])
        XCTAssertEqual(s2, Social.Score(target: target, likes: 1, dislikes: 1))   // two distinct humans
    }

    /// Reports dedupe by distinct reporter per target (no manufactured pile-on).
    func testReportCountsDistinctReporters() throws {
        let a = try kp(1), b = try kp(2)
        let r1 = try Social.fileReport(a, target: target, reason: "spam", epoch: 1)
        let r1again = try Social.fileReport(a, target: target, reason: "harm", epoch: 2)   // same reporter
        let r2 = try Social.fileReport(b, target: target, reason: "abuse", epoch: 1)
        let counts = Social.reportCounts([r1, r1again, r2])
        XCTAssertEqual(counts[target], 2, "same reporter counts once; two distinct reporters -> 2")
    }
}
