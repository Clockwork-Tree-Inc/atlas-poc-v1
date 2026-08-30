import Foundation

/// Anonymous revocation on blst — a bilinear accumulator (Nguyen/CL) plus an unlinkable zero-knowledge
/// membership proof. Parity with backend/atlas/realid/anon_revocation.py. Revoke once and that
/// credential's showings fail everywhere; the ZK proof hides which handle is shown.
public enum Revocation {

    public static func handle(_ seed: Data) -> Fr { Fr.hash([Data("atlas/anon-revoc/handle/v1".utf8), seed]) }

    /// Issuer-side accumulator authority: secret `alpha`, public `pub = g2^alpha`, and the member set.
    public final class Registry {
        public let alpha: Fr
        public let pub: G2
        public private(set) var members: [Fr] = []

        public init() {
            let a = Fr.random()
            self.alpha = a
            self.pub = G2.generator.mul(a)
        }

        private func accOver(_ handles: [Fr]) -> G1 {
            var exp = Fr.one
            for h in handles { exp = exp * (alpha + h) }
            return G1.generator.mul(exp)
        }

        public func addMember(_ h: Fr) {
            if !members.contains(where: { $0 == h }) { members.append(h) }
        }
        public func accumulator() -> G1 { accOver(members) }
        public func witness(_ h: Fr) -> G1? {
            guard members.contains(where: { $0 == h }) else { return nil }
            return accOver(members.filter { !($0 == h) })
        }
        public func revoke(_ h: Fr) { members.removeAll { $0 == h } }
    }

    /// Public membership check (no alpha): e(w, g2^alpha·g2^id) == e(Acc, g2). Reveals the handle — use
    /// the ZK form for unlinkable revocation checking.
    public static func verifyMembership(_ pub: G2, _ acc: G1, handle: Fr, witness: G1) -> Bool {
        guard witness.isValid(), acc.isValid() else { return false }
        return GT.pairing(witness, pub + G2.generator.mul(handle)) == GT.pairing(acc, G2.generator)
    }

    // MARK: unlinkable ZK membership proof
    // From w^{alpha+id}=Acc, blind w̄=w^ρ: e(w̄,g2)^id · e(Acc,g2)^{-ρ} = e(w̄,P)^{-1}. Prove knowledge
    // of (id, ρ) — a two-secret DL statement in GT, over the REAL public accumulator.

    public struct MembershipProof: Sendable {
        public let wbar: G1
        public let commitment: G1      // Schnorr commitment Rg1 in G1 (portable; keeps GT out of the hash)
        public let challenge: Fr
        public let zId: Fr
        public let zRho: Fr
    }

    private static func memChallenge(_ pub: G2, _ acc: G1, _ wbar: G1, _ commitment: G1, _ nonce: Data) -> Fr {
        Fr.hash([Data("atlas/anon-revoc-zk/v1".utf8), Data(pub.serialize()), Data(acc.serialize()),
                 Data(wbar.serialize()), Data(commitment.serialize()), nonce])
    }

    public static func proveMembership(_ pub: G2, _ acc: G1, handle: Fr, witness: G1, nonce: Data) -> MembershipProof {
        let rho = Fr.random()
        let wbar = witness.mul(rho)
        let k1 = Fr.random(), k2 = Fr.random()
        let Rg1 = wbar.mul(k1) + acc.mul(k2)           // k1*wbar + k2*Acc (G1)
        let c = memChallenge(pub, acc, wbar, Rg1, nonce)
        let zId = k1 + c * handle
        let zRho = k2 + c * rho.negated                // exponent for B2 is -rho
        return MembershipProof(wbar: wbar, commitment: Rg1, challenge: c, zId: zId, zRho: zRho)
    }

    public static func verifyMembershipZK(_ pub: G2, _ acc: G1, _ proof: MembershipProof, nonce: Data) -> Bool {
        guard proof.wbar.isValid(), proof.commitment.isValid(), acc.isValid() else { return false }
        let c = proof.challenge
        guard memChallenge(pub, acc, proof.wbar, proof.commitment, nonce) == c else { return false }
        // e(Rg1, g2) == e(zId*wbar + zRho*Acc, g2) * e(c*wbar, P)
        let M = proof.wbar.mul(proof.zId) + acc.mul(proof.zRho)
        let N = proof.wbar.mul(c)
        let lhs = GT.pairing(proof.commitment, G2.generator)
        let rhs = GT.pairing(M, G2.generator) * GT.pairing(N, pub)
        return lhs == rhs
    }
}
