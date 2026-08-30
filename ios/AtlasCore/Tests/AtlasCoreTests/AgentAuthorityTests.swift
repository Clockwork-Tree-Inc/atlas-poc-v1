import XCTest
@testable import AtlasCore

final class AgentAuthorityTests: XCTestCase {
    typealias AD = AgentDelegation
    private func kp(_ n: UInt8) -> HybridSign.Keypair { try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32)) }
    private let NOW = 100
    private let space = Data("space:market".utf8)

    private func profile(_ k: HybridSign.Keypair, _ ec: EntityClass = .individual) -> ParticipantProfile {
        ParticipantProfile(handle: Data(repeating: 9, count: 32), publicKey: k.publicKey, entityClass: ec)
    }
    private func giveRealID(_ p: ParticipantProfile, _ issuer: Issuers.Issuer) throws {
        try p.hold(try issuer.issueRealID(subject: p.handle))
    }
    private func chain(_ root: HybridSign.Keypair, _ agent: HybridSign.Keypair, caps: [String],
                       _ cls: EntityClass = .individual) throws -> [AD.Delegation] {
        [try AD.delegate(root, principalClass: cls, agent: agent.publicKey, capabilities: caps,
                         scope: space, notAfter: 200)]
    }

    func testCredentialedRootLetsAgentSell() throws {
        let human = kp(1), agent = kp(2)
        let p = profile(human)
        let verifier = Issuers.Issuer(kp(5), name: "V")
        try giveRealID(p, verifier)
        let c = try chain(human, agent, caps: ["sell"])
        XCTAssertTrue(try AgentAuthority.agentMaySupply(chain: c, action: "sell", scope: space, now: NOW,
                                                        rootProfile: p, trustedVerifierKeys: [verifier.publicKey.encode()]))
    }

    func testUncredentialedRootCannotSell() throws {
        let human = kp(1), agent = kp(2)
        let p = profile(human)                       // no real-id
        let c = try chain(human, agent, caps: ["sell"])
        XCTAssertFalse(try AgentAuthority.agentMaySupply(chain: c, action: "sell", scope: space, now: NOW,
                                                         rootProfile: p, trustedVerifierKeys: [kp(5).publicKey.encode()]))
    }

    func testAgentSelfDeclaringRootRejected() throws {
        let rogue = kp(1), sub = kp(2)
        let p = profile(rogue, .agent)
        let c = try chain(rogue, sub, caps: ["sell"], .agent)   // agent-rooted chain
        XCTAssertFalse(try AgentAuthority.agentMaySupply(chain: c, action: "sell", scope: space, now: NOW,
                                                         rootProfile: p, trustedVerifierKeys: []))
    }

    func testCapabilityNotGrantedRejected() throws {
        let human = kp(1), agent = kp(2)
        let p = profile(human)
        let verifier = Issuers.Issuer(kp(5), name: "V")
        try giveRealID(p, verifier)
        let c = try chain(human, agent, caps: ["read"])          // only read
        XCTAssertFalse(try AgentAuthority.agentMaySupply(chain: c, action: "sell", scope: space, now: NOW,
                                                         rootProfile: p, trustedVerifierKeys: [verifier.publicKey.encode()]))
    }

    func testOrgRootNeedsRegistration() throws {
        let officer = kp(1), agent = kp(2)
        let org = profile(officer, .forProfit)
        let verifier = Issuers.Issuer(kp(5), name: "V"), registry = Issuers.Issuer(kp(6), name: "Reg")
        try giveRealID(org, verifier)
        let vkeys = Set([verifier.publicKey.encode()]); let rkeys = Set([registry.publicKey.encode()])
        let c = try chain(officer, agent, caps: ["sell"], .forProfit)
        XCTAssertFalse(try AgentAuthority.agentMaySupply(chain: c, action: "sell", scope: space, now: NOW,
                                                         rootProfile: org, trustedVerifierKeys: vkeys, trustedRegistryKeys: rkeys))
        try org.hold(try registry.issueRegistration(subject: org.handle))
        XCTAssertTrue(try AgentAuthority.agentMaySupply(chain: c, action: "sell", scope: space, now: NOW,
                                                        rootProfile: org, trustedVerifierKeys: vkeys, trustedRegistryKeys: rkeys))
    }
}
