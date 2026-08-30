import XCTest
@testable import AtlasCore

final class AgentDelegationTests: XCTestCase {
    typealias AD = AgentDelegation
    private func kp(_ n: UInt8) -> HybridSign.Keypair { try! HybridSign.keypair(fromSeed: Data(repeating: n, count: 32)) }
    private let NOW = 100
    private let space = Data("space:acme".utf8)

    func testIndividualDelegatesToAgent() throws {
        let human = kp(1), agent = kp(2)
        let d = try AD.delegate(human, principalClass: .individual, agent: agent.publicKey,
                                capabilities: ["read", "post"], scope: space, notAfter: 200)
        XCTAssertTrue(AD.verifyLink(d, now: NOW))
        XCTAssertTrue(AD.verifyChain([d], now: NOW))
        XCTAssertTrue(AD.authorized([d], capability: "post", scope: space, now: NOW))
        XCTAssertFalse(AD.authorized([d], capability: "delete", scope: space, now: NOW))
    }

    func testBusinessCanBePrincipal() throws {
        let biz = kp(1), agent = kp(2)
        let d = try AD.delegate(biz, principalClass: .forProfit, agent: agent.publicKey,
                                capabilities: ["sell"], scope: space, notAfter: 200)
        XCTAssertTrue(AD.verifyChain([d], now: NOW))
        let (_, cls) = try AD.rootPrincipal([d])
        XCTAssertEqual(cls, .forProfit)
    }

    func testAgentCannotBeRootPrincipal() throws {
        let rogue = kp(1), sub = kp(2)
        let d = try AD.delegate(rogue, principalClass: .agent, agent: sub.publicKey,
                                capabilities: ["read"], scope: space, notAfter: 200)
        XCTAssertFalse(AD.verifyLink(d, now: NOW))
        XCTAssertFalse(AD.verifyChain([d], now: NOW))
    }

    func testExpiredInvalid() throws {
        let human = kp(1), agent = kp(2)
        let d = try AD.delegate(human, principalClass: .individual, agent: agent.publicKey,
                                capabilities: ["read"], scope: space, notAfter: 50)
        XCTAssertFalse(AD.verifyLink(d, now: NOW))
    }

    func testTamperedFails() throws {
        let human = kp(1), agent = kp(2)
        var d = try AD.delegate(human, principalClass: .individual, agent: agent.publicKey,
                                capabilities: ["read"], scope: space, notAfter: 200)
        d = AD.Delegation(principal: d.principal, principalClass: d.principalClass, agent: d.agent,
                          capabilities: ["read", "admin"], scope: d.scope, notAfter: d.notAfter,
                          parent: d.parent, sig: d.sig)   // add capability after signing
        XCTAssertFalse(AD.verifyLink(d, now: NOW))
    }

    func testValidSubdelegationAttenuatesAndRoots() throws {
        let human = kp(1), planner = kp(2), worker = kp(3)
        let root = try AD.delegate(human, principalClass: .individual, agent: planner.publicKey,
                                   capabilities: ["read", "post", "pay"], scope: Data(), notAfter: 300)
        let sub = try AD.delegate(planner, principalClass: .agent, agent: worker.publicKey,
                                  capabilities: ["read"], scope: space, notAfter: 250, parent: root.id())
        let chain = [root, sub]
        XCTAssertTrue(AD.verifyChain(chain, now: NOW))
        XCTAssertTrue(AD.authorized(chain, capability: "read", scope: space, now: NOW))
        XCTAssertFalse(AD.authorized(chain, capability: "pay", scope: space, now: NOW))
        let (_, cls) = try AD.rootPrincipal(chain)
        XCTAssertEqual(cls, .individual)
    }

    func testSubdelegationCannotWiden() throws {
        let human = kp(1), planner = kp(2), worker = kp(3)
        let root = try AD.delegate(human, principalClass: .individual, agent: planner.publicKey,
                                   capabilities: ["read"], scope: Data(), notAfter: 300)
        let wider = try AD.delegate(planner, principalClass: .agent, agent: worker.publicKey,
                                    capabilities: ["read", "pay"], scope: Data(), notAfter: 300, parent: root.id())
        XCTAssertFalse(AD.verifyChain([root, wider], now: NOW))
    }

    func testSubdelegationCannotOutliveParent() throws {
        let human = kp(1), planner = kp(2), worker = kp(3)
        let root = try AD.delegate(human, principalClass: .individual, agent: planner.publicKey,
                                   capabilities: ["read"], scope: Data(), notAfter: 200)
        let longer = try AD.delegate(planner, principalClass: .agent, agent: worker.publicKey,
                                     capabilities: ["read"], scope: Data(), notAfter: 999, parent: root.id())
        XCTAssertFalse(AD.verifyChain([root, longer], now: NOW))
    }

    func testBrokenChainLinkFails() throws {
        let human = kp(1), planner = kp(2), worker = kp(3), imposter = kp(4)
        let root = try AD.delegate(human, principalClass: .individual, agent: planner.publicKey,
                                   capabilities: ["read"], scope: Data(), notAfter: 300)
        let orphan = try AD.delegate(imposter, principalClass: .agent, agent: worker.publicKey,
                                     capabilities: ["read"], scope: Data(), notAfter: 300, parent: root.id())
        XCTAssertFalse(AD.verifyChain([root, orphan], now: NOW))
    }

    func testGlobalScopeCoversAny() throws {
        let human = kp(1), agent = kp(2)
        let d = try AD.delegate(human, principalClass: .individual, agent: agent.publicKey,
                                capabilities: ["read"], scope: Data(), notAfter: 300)
        XCTAssertTrue(AD.authorized([d], capability: "read", scope: Data("any".utf8), now: NOW))
    }

    func testEntityClassHelpers() {
        XCTAssertTrue(EntityClass.forProfit.isOrganization && EntityClass.nonprofit.isOrganization)
        XCTAssertFalse(EntityClass.individual.isOrganization || EntityClass.agent.isOrganization)
        XCTAssertTrue(EntityClass.individual.canBePrincipal && EntityClass.forProfit.canBePrincipal)
        XCTAssertFalse(EntityClass.agent.canBePrincipal)
    }
}
