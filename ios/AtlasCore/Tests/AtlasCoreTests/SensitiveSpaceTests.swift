import XCTest
@testable import AtlasCore

final class SensitiveSpaceTests: XCTestCase {
    typealias SS = SensitiveSpaceNS
    typealias SG = SpaceGovernance
    private let FILE = Data("Dx: sensitive.".utf8)
    private func kp(_ n: UInt8) -> HybridSign.Keypair { try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32)) }
    private func key() -> Data { Primitives.randomBytes(32) }

    private func space(_ owner: HybridSign.Keypair, _ ck: Data) throws -> SS.SensitiveSpace {
        SS.SensitiveSpace(policy: SG.SpacePolicy.genesis(spaceID: Data("space:clinic".utf8), creator: owner.publicKey),
                          record: try Records.sealRecord(FILE, contentKey: ck),
                          log: Records.AccessLog())
    }
    private func grant(_ p: SG.SpacePolicy, _ owner: HybridSign.Keypair, _ who: HybridSign.Keypair, _ role: SG.Role, _ epoch: Int) throws {
        let ch = try p.propose("grant", target: who.publicKey, role: role, epoch: epoch)
        try p.authorize(ch, approvals: [(owner.publicKey, try HybridSign.sign(owner, ch.body()))])
    }

    func testMemberReaderOpensNonMemberBlocked() throws {
        let owner = kp(1), patient = kp(2), stranger = kp(9)
        let ck = key()
        let s = try space(owner, ck)
        try grant(s.policy, owner, patient, .reader, 1)
        XCTAssertEqual(try SS.openOwn(s, member: patient.publicKey, contentKey: ck, nowRound: 10), FILE)
        XCTAssertThrowsError(try SS.openOwn(s, member: stranger.publicKey, contentKey: ck, nowRound: 11))
    }

    func testRoleGatesWhoRecordsGatesWhen() throws {
        let owner = kp(1), oncall = kp(3)
        let ck = key(), bg = key()
        let s = try space(owner, ck)
        try grant(s.policy, owner, oncall, .reader, 1)   // only reader
        let wrapped = try Primitives.aeadEncrypt(key: bg, plaintext: ck)
        XCTAssertThrowsError(try SS.breakGlass(s, member: oncall.publicKey, breakGlassKey: bg,
                                               wrappedContentKey: wrapped, nowRound: 5))
        try grant(s.policy, owner, oncall, .breakGlass, 2)
        XCTAssertEqual(try SS.breakGlass(s, member: oncall.publicKey, breakGlassKey: bg,
                                         wrappedContentKey: wrapped, nowRound: 6), FILE)
        XCTAssertEqual(s.log.notifications().count, 1)
    }

    func testReopenThresholdStillApplies() throws {
        let owner = kp(1)
        let ck = key()
        let s = try space(owner, ck)
        let (doctor, body) = Records.splitReopenShares(ck)
        XCTAssertEqual(try SS.reopenDispute(s, doctorShare: doctor, bodyShare: body, nowRound: 5, retentionEnd: 1000), FILE)
        XCTAssertThrowsError(try SS.reopenDispute(s, doctorShare: doctor, bodyShare: body, nowRound: 2000, retentionEnd: 1000))
    }
}
