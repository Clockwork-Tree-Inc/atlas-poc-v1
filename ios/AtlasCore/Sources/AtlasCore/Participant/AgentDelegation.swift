import Foundation

/// Agent delegation — the cryptographic LEASH that makes an AI agent a safe first-class participant.
/// Byte-for-byte parity with `backend/atlas/agent_delegation.py` (Python is reference-of-record).
///
/// An agent is never a root actor: it acts only under a DELEGATION signed by a principal, scoped to
/// capabilities + a space, expiring at an epoch. A chain of delegations must terminate at a non-agent
/// root (individual/business) — so "who did this?" always resolves to a responsible party, and there
/// is no autonomous authority with no one behind it. Sub-delegation may only NARROW authority.
public enum AgentDelegation {

    static let delegLabel = Data("atlas/agent-delegation/v1".utf8)
    static let delegIDLabel = Data("atlas/agent-delegation-id/v1".utf8)

    static func lp(_ d: Data) -> Data {
        var n = UInt32(d.count).bigEndian
        return withUnsafeBytes(of: &n) { Data($0) } + d
    }
    static func u32(_ v: Int) -> Data { var n = UInt32(v).bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }
    static func u64(_ v: Int) -> Data { var n = UInt64(v).bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }

    public enum DelegationError: Error { case emptyChain }

    public struct Delegation {
        public let principal: HybridSign.PublicKey
        public let principalClass: EntityClass
        public let agent: HybridSign.PublicKey
        public let capabilities: [String]
        public let scope: Data                 // a space id, or empty for global
        public let notAfter: Int               // expiry epoch (inclusive)
        public let parent: Data                 // parent delegation id, or empty if rooted
        public var sig: Data

        public init(principal: HybridSign.PublicKey, principalClass: EntityClass,
                    agent: HybridSign.PublicKey, capabilities: [String], scope: Data,
                    notAfter: Int, parent: Data = Data(), sig: Data = Data()) {
            self.principal = principal; self.principalClass = principalClass; self.agent = agent
            self.capabilities = capabilities; self.scope = scope; self.notAfter = notAfter
            self.parent = parent; self.sig = sig
        }

        public func body() -> Data {
            let caps = Array(Set(capabilities)).sorted()
            var buf = delegLabel + lp(principal.encode()) + lp(Data(principalClass.rawValue.utf8))
                + lp(agent.encode()) + u32(caps.count)
            for c in caps { buf += lp(Data(c.utf8)) }
            buf += lp(scope) + u64(notAfter) + lp(parent)
            return buf
        }

        public func id() -> Data { Primitives.H(delegIDLabel, body()) }
    }

    public static func delegate(_ principalKp: HybridSign.Keypair, principalClass: EntityClass,
                                agent: HybridSign.PublicKey, capabilities: [String], scope: Data,
                                notAfter: Int, parent: Data = Data()) throws -> Delegation {
        var d = Delegation(principal: principalKp.publicKey, principalClass: principalClass, agent: agent,
                           capabilities: capabilities, scope: scope, notAfter: notAfter, parent: parent)
        d.sig = try HybridSign.sign(principalKp, d.body())
        return d
    }

    public static func verifyLink(_ d: Delegation, now: Int) -> Bool {
        guard HybridSign.verify(d.principal, d.body(), d.sig) else { return false }
        guard now <= d.notAfter else { return false }
        if d.parent.isEmpty { return d.principalClass.canBePrincipal }   // root link: non-agent only
        return true
    }

    static func scopeWithin(_ child: Data, _ parent: Data) -> Bool {
        parent.isEmpty || child == parent
    }

    public static func verifyChain(_ chain: [Delegation], now: Int) -> Bool {
        guard let root = chain.first else { return false }
        if !root.parent.isEmpty || !root.principalClass.canBePrincipal { return false }
        for (i, d) in chain.enumerated() {
            if !verifyLink(d, now: now) { return false }
            if i == 0 { continue }
            let prev = chain[i - 1]
            if d.parent != prev.id() { return false }
            if d.principal.encode() != prev.agent.encode() { return false }
            if !Set(d.capabilities).isSubset(of: Set(prev.capabilities)) { return false }
            if !scopeWithin(d.scope, prev.scope) { return false }
            if d.notAfter > prev.notAfter { return false }
        }
        return true
    }

    public static func authorized(_ chain: [Delegation], capability: String, scope: Data, now: Int) -> Bool {
        guard verifyChain(chain, now: now), let leaf = chain.last else { return false }
        return leaf.capabilities.contains(capability) && scopeWithin(scope, leaf.scope)
    }

    public static func rootPrincipal(_ chain: [Delegation]) throws -> (HybridSign.PublicKey, EntityClass) {
        guard let root = chain.first else { throw DelegationError.emptyChain }
        return (root.principal, root.principalClass)
    }
}
