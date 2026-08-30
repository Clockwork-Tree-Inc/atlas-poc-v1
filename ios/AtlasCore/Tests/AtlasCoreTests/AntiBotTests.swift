import XCTest
@testable import AtlasCore

/// Phone-only anti-bot protocol + offline verifier (Swift), parity with
/// `backend/atlas/liveness/antibot.py`.
final class AntiBotTests: XCTestCase {
    private func kp() throws -> HybridSign.Keypair { try HybridSign.keypair(fromSeed: Primitives.randomBytes(32)) }

    func testResponseBodyParityKAT() throws {
        let r = AntiBot.Response(nonce: Data(count: 16), kind: "gesture",
                                 motionSummary: Data("m".utf8), publicKey: try kp().publicKey)
        let hex = r.body().map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(hex, "161cb393d91f353e4232337983c1cb295caeab4a8ede0c6a9aade60c01a8da26")
    }

    func testFreshChallengeVerifies() throws {
        let k = try kp(); let v = AntiBot.Verifier()
        let ch = AntiBot.issueChallenge(epoch: 1)
        let r = try AntiBot.respond(ch, motionSummary: Data("imu+tap+entropy".utf8), keypair: k, publicKey: k.publicKey)
        XCTAssertTrue(v.verify(r, ch))
    }

    func testReplayRejectedOneShot() throws {
        let k = try kp(); let v = AntiBot.Verifier()
        let ch = AntiBot.issueChallenge(epoch: 1)
        let r = try AntiBot.respond(ch, motionSummary: Data("m".utf8), keypair: k, publicKey: k.publicKey)
        XCTAssertTrue(v.verify(r, ch))
        XCTAssertFalse(v.verify(r, ch))
    }

    func testWrongChallengeNoSignalAndForgedRejected() throws {
        let k = try kp(); let other = try kp(); let v = AntiBot.Verifier()
        let ch1 = AntiBot.issueChallenge(epoch: 1); let ch2 = AntiBot.issueChallenge(epoch: 1)
        let r = try AntiBot.respond(ch1, motionSummary: Data("m".utf8), keypair: k, publicKey: k.publicKey)
        XCTAssertFalse(v.verify(r, ch2))                                             // wrong challenge
        let empty = try AntiBot.respond(ch1, motionSummary: Data(), keypair: k, publicKey: k.publicKey)
        XCTAssertFalse(v.verify(empty, ch1))                                         // no physical signal
        var forged = try AntiBot.respond(ch1, motionSummary: Data("m".utf8), keypair: k, publicKey: k.publicKey)
        forged.publicKey = other.publicKey                                           // claim a different signer
        XCTAssertFalse(v.verify(forged, ch1))
    }
}
