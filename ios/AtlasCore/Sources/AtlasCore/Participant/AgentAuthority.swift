import Foundation

/// Agent authority — the ONE enforcement point that composes the leash and the gate. Parity with
/// `backend/atlas/agent_authority.py`. `principalClass` inside a delegation is self-declared, so on
/// its own an agent key could mint itself a root delegation claiming to be an individual. This is the
/// only sanctioned way to ask "may this agent, via its chain, perform this action?" — it cross-checks
/// the chain's root against a REAL credential (the root must pass the Real-ID supply gate).
public enum AgentAuthority {

    /// True iff: the chain is valid; the root profile IS the chain's root principal (same key + class);
    /// the agent's leaf grants the capability in scope; AND the root passes the Real-ID supply gate.
    public static func agentMaySupply(chain: [AgentDelegation.Delegation], action: String, scope: Data,
                                      now: Int, rootProfile: ParticipantProfile, capability: String? = nil,
                                      trustedVerifierKeys: Set<Data> = [],
                                      trustedRegistryKeys: Set<Data> = []) throws -> Bool {
        guard AgentDelegation.verifyChain(chain, now: now) else { return false }
        let (rootPub, rootClass) = try AgentDelegation.rootPrincipal(chain)
        guard rootProfile.publicKey.encode() == rootPub.encode() else { return false }
        guard rootProfile.entityClass == rootClass else { return false }
        guard AgentDelegation.authorized(chain, capability: capability ?? action, scope: scope, now: now) else { return false }
        return try SupplyGate.canPerform(rootProfile, action: action,
                                         trustedVerifierKeys: trustedVerifierKeys,
                                         trustedRegistryKeys: trustedRegistryKeys)
    }
}
