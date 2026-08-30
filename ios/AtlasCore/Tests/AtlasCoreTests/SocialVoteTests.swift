import XCTest
@testable import AtlasCore

/// The app-facing `Social.castVote(by: Profile…)`: a persona is one last-wins vote per target,
/// and two personas are distinct voters (per-persona nullifier).
final class SocialVoteTests: XCTestCase {
    func testPersonaCastVoteDedupesPerPersonaLastWins() throws {
        let tree = try IdentityTree.build(tskSeed: Primitives.randomBytes(32), sphincs: StubSphincs())
        let p = try tree.profile("alice")
        let target = Data("item-1".utf8)
        let v1 = try Social.castVote(by: p, target: target, up: true, epoch: 0)
        let v2 = try Social.castVote(by: p, target: target, up: false, epoch: 1)
        let score = Social.tally(target: target, votes: [v1, v2])
        XCTAssertEqual(score.likes, 0)
        XCTAssertEqual(score.dislikes, 1)                 // same persona: last vote wins

        let q = try tree.profile("bob")
        let v3 = try Social.castVote(by: q, target: target, up: true, epoch: 0)
        let s2 = Social.tally(target: target, votes: [v1, v2, v3])
        XCTAssertEqual(s2.likes, 1)
        XCTAssertEqual(s2.dislikes, 1)                    // distinct persona = distinct voter
    }
}
