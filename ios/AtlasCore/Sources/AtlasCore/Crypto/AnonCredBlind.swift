import Foundation

/// PS blind issuance on blst — the issuer signs a credential WITHOUT seeing the hidden messages (the
/// master secret). Parity with the blind_request / blind_sign / blind_unblind flow in ps_credential.py:
/// the holder commits C = g1^t * prod Yg1_i^{m_i} with a Schnorr PoK, the issuer folds in its secret and
/// the disclosed messages homomorphically, the holder unblinds to a standard PS signature.
extension PS {

    public struct BlindRequest: Sendable {
        public let C: G1
        public let hiddenIdx: [Int]
        public let challenge: Fr
        public let responses: [Fr]        // for bases (g1, Yg1_hidden…)
    }

    public enum BlindError: Error { case badCommitment, indexOverlap, indexCoverage, proofInvalid }

    private static func multibase(_ bases: [G1], _ scalars: [Fr]) -> G1 {
        var acc: G1? = nil
        for (b, s) in zip(bases, scalars) {
            let term = b.mul(s)
            acc = acc == nil ? term : acc! + term
        }
        return acc ?? G1.generator.mul(Fr.zero)
    }

    private static func pokContext(_ pub: PublicKey, _ bases: [G1]) -> Data {
        var d = Data(pub.bytes())
        for b in bases { d.append(Data(b.serialize())) }
        return d
    }

    private static func schnorrProve(_ bases: [G1], _ secrets: [Fr], _ C: G1, _ ctx: Data) -> (Fr, [Fr]) {
        let ks = bases.map { _ in Fr.random() }
        let A = multibase(bases, ks)
        let c = Fr.hash([Data("atlas/ps-blind-pok/v1".utf8), ctx, Data(C.serialize()), Data(A.serialize())])
        let z = zip(ks, secrets).map { $0 + c * $1 }
        return (c, z)
    }

    private static func schnorrVerify(_ bases: [G1], _ C: G1, _ c: Fr, _ z: [Fr], _ ctx: Data) -> Bool {
        guard z.count == bases.count else { return false }
        let Ap = multibase(bases, z) + C.mul(c.negated)   // prod bases^z * C^{-c}
        let c2 = Fr.hash([Data("atlas/ps-blind-pok/v1".utf8), ctx, Data(C.serialize()), Data(Ap.serialize())])
        return c2 == c
    }

    private static func pokBases(_ pub: PublicKey, _ hiddenIdx: [Int]) -> [G1] {
        [G1.generator] + hiddenIdx.map { pub.Yg1[$0] }
    }

    /// Holder: commit to the hidden messages and prove knowledge. Returns the request + blinding `t`.
    public static func blindRequest(_ pub: PublicKey, hidden: [Int: Fr]) -> (BlindRequest, Fr) {
        let hiddenIdx = hidden.keys.sorted()
        let t = Fr.random()
        let bases = pokBases(pub, hiddenIdx)
        let secrets = [t] + hiddenIdx.map { hidden[$0]! }
        let C = multibase(bases, secrets)
        let (c, z) = schnorrProve(bases, secrets, C, pokContext(pub, bases))
        return (BlindRequest(C: C, hiddenIdx: hiddenIdx, challenge: c, responses: z), t)
    }

    /// Issuer: verify the PoK and blind-sign, disclosing only `disclosed`. Never sees the hidden values.
    public static func blindSign(_ sk: SecretKey, _ req: BlindRequest, disclosed: [Int: Fr]) throws -> Signature {
        let pub = sk.pub
        guard req.C.isValid() else { throw BlindError.badCommitment }
        let hiddenSet = Set(req.hiddenIdx), discSet = Set(disclosed.keys)
        guard hiddenSet.isDisjoint(with: discSet) else { throw BlindError.indexOverlap }
        guard hiddenSet.union(discSet) == Set(0..<pub.n) else { throw BlindError.indexCoverage }
        let bases = pokBases(pub, req.hiddenIdx)
        guard schnorrVerify(bases, req.C, req.challenge, req.responses, pokContext(pub, bases)) else {
            throw BlindError.proofInvalid
        }
        let u = Fr.random()
        var acc = G1.generator.mul(sk.x) + req.C
        for (i, m) in disclosed { acc = acc + pub.Yg1[i].mul(m) }
        return Signature(s1: G1.generator.mul(u), s2: acc.mul(u))
    }

    /// Holder: strip the blinding -> a standard PS signature on all messages.
    public static func blindUnblind(_ blinded: Signature, blinding t: Fr) -> Signature {
        Signature(s1: blinded.s1, s2: blinded.s2 + blinded.s1.mul(t.negated))
    }
}
