import XCTest
@testable import AtlasCore

/// Polls — Sybil-free, one-human-one-response, at three anonymity levels.
/// Mirrors `backend/tests/test_polls.py`.
final class PollsTests: XCTestCase {

    private func kp(_ n: UInt8) -> HybridSign.Keypair {
        try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32))
    }
    private let opts = [Data("yes".utf8), Data("no".utf8), Data("maybe".utf8)]

    private func poll(_ tier: Spaces.IdentityTier = .verifiedPerson) throws -> Spaces.Poll {
        try Spaces.createPoll(kp(1), question: Data("ship it?".utf8), options: opts, tier: tier, epoch: 1)
    }

    func testCreateAndVerifyPoll() throws {
        var p = try poll()
        XCTAssertTrue(Spaces.verifyPoll(p))
        p.question = Data("tampered".utf8)
        XCTAssertFalse(Spaces.verifyPoll(p))
    }

    func testPseudonymousTally() throws {
        let p = try poll(.pseudonymous)
        let rs = try [
            Spaces.respond(kp(2), poll: p, choice: 0, nullifier: Data("h2".utf8), epoch: 1),
            Spaces.respond(kp(3), poll: p, choice: 0, nullifier: Data("h3".utf8), epoch: 1),
            Spaces.respond(kp(4), poll: p, choice: 1, nullifier: Data("h4".utf8), epoch: 1),
        ]
        let res = Spaces.tally(p, rs)
        XCTAssertEqual(res.counts, [2, 1, 0])
        XCTAssertEqual(res.total, 3)
        XCTAssertEqual(res.winner(), 0)
    }

    func testOneHumanOneResponseLastWins() throws {
        let p = try poll()
        let rs = try [
            Spaces.respond(kp(2), poll: p, choice: 0, nullifier: Data("A".utf8), epoch: 1),
            Spaces.respond(kp(2), poll: p, choice: 1, nullifier: Data("A".utf8), epoch: 2),
        ]
        let res = Spaces.tally(p, rs)
        XCTAssertEqual(res.counts, [0, 1, 0])
        XCTAssertEqual(res.total, 1)
    }

    func testSybilAcrossPersonasDeduped() throws {
        let p = try poll()
        let rs = try [2, 3, 4].map {
            try Spaces.respond(kp(UInt8($0)), poll: p, choice: 0, nullifier: Data("one".utf8), epoch: 1)
        }
        let res = Spaces.tally(p, rs)
        XCTAssertEqual(res.total, 1)
        XCTAssertEqual(res.counts, [1, 0, 0])
    }

    func testAnonymousBallotUnlinkableButCounts() throws {
        let p = try poll(.anonymous)
        let voter = kp(2)
        let eph = kp(200)
        let r = try Spaces.respondAnonymously(p, choice: 2, nullifier: Data("h2".utf8), epoch: 1, ephemeralKp: eph)
        XCTAssertNotEqual(r.ballotKey.encode(), voter.publicKey.encode())   // not the persona
        XCTAssertEqual(r.ballotKey.encode(), eph.publicKey.encode())
        XCTAssertTrue(Spaces.verifyResponse(p, r))
        XCTAssertEqual(Spaces.tally(p, [r]).counts, [0, 0, 1])
    }

    func testTamperedResponseRejected() throws {
        let p = try poll()
        var r = try Spaces.respond(kp(2), poll: p, choice: 0, nullifier: Data("h2".utf8), epoch: 1)
        r.choice = 1
        XCTAssertFalse(Spaces.verifyResponse(p, r))
        XCTAssertEqual(Spaces.tally(p, [r]).total, 0)
    }

    func testResponseForOtherPollIgnored() throws {
        let p = try poll()
        let other = try Spaces.createPoll(kp(9), question: Data("other".utf8), options: opts,
                                          tier: .pseudonymous, epoch: 1)
        let r = try Spaces.respond(kp(2), poll: other, choice: 0, nullifier: Data("h2".utf8), epoch: 1)
        XCTAssertEqual(Spaces.tally(p, [r]).total, 0)
    }
}
