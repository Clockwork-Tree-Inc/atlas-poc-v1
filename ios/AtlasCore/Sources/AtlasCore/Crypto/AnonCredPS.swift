import Foundation

/// Pointcheval-Sanders anonymous credential on blst — the on-device sibling of
/// backend/atlas/realid/ps_credential.py. A credential signs n messages; the holder shows unlimited,
/// re-randomised, mutually-unlinkable proofs that reveal a chosen subset and hide the rest (the master
/// secret, a revocation handle) with a Schnorr proof over the target group.
///
/// This is the holder-side machinery that must run on the phone. It is self-consistent (Swift proves
/// and verifies), and credentials (G1 points) share the Python serialization so a backend-issued
/// credential can be held and shown here.
public enum PS {

    public struct PublicKey: Sendable {
        public let Xt: G2                 // g2^x
        public let Yt: [G2]               // g2^{y_i}
        public let Yg1: [G1]              // g1^{y_i} (for blind issuance)
        public let n: Int

        func bytes() -> [UInt8] {
            var out = Xt.rawBytes()
            for y in Yt { out += y.rawBytes() }
            var nn = UInt32(n).bigEndian
            withUnsafeBytes(of: &nn) { out += Array($0) }
            return out
        }
    }

    public struct SecretKey: Sendable {
        public let x: Fr
        public let y: [Fr]
        public let pub: PublicKey
    }

    public struct Signature: Sendable {   // (s1, s2) in G1
        public let s1: G1
        public let s2: G1
    }

    public struct Proof: Sendable {
        public let s1: G1
        public let s2: G1
        public let commitment: G2         // Schnorr commitment R in G2 (portable; keeps GT out of the hash)
        public let reveal: [Int]
        public let revealedVals: [Fr]
        public let responses: [Fr]        // hidden-message responses (ascending index) then t-response
        public let challenge: Fr
    }

    // MARK: keygen / sign

    public static func keygen(_ n: Int) -> SecretKey {
        let x = Fr.random()
        let ys = (0..<n).map { _ in Fr.random() }
        let g2 = G2.generator, g1 = G1.generator
        let pub = PublicKey(Xt: g2.mul(x), Yt: ys.map { g2.mul($0) }, Yg1: ys.map { g1.mul($0) }, n: n)
        return SecretKey(x: x, y: ys, pub: pub)
    }

    public static func sign(_ sk: SecretKey, messages: [Fr]) -> Signature {
        precondition(messages.count == sk.pub.n)
        let u = Fr.random()
        let s1 = G1.generator.mul(u)
        var e = sk.x
        for (yi, mi) in zip(sk.y, messages) { e = e + yi * mi }
        return Signature(s1: s1, s2: s1.mul(e))
    }

    // MARK: present / verify

    /// The transcript hashed into the challenge — ONE concatenated blob (matches the Python
    /// _transcript), of ONLY G1/G2 elements + scalars, so the challenge is identical cross-language.
    private static func transcript(_ s1: G1, _ s2: G1, _ commitment: G2, _ reveal: [Int], _ vals: [Fr],
                                   _ nonce: Data) -> Data {
        var d = Data(s1.serialize()); d.append(Data(s2.serialize())); d.append(Data(commitment.serialize()))
        d.append(nonce)
        for (i, v) in zip(reveal, vals) {
            d.append(Data([UInt8((i >> 8) & 0xff), UInt8(i & 0xff)]))
            d.append(Data(v.bytesBE()))
        }
        return d
    }

    private static func challenge(_ pub: PublicKey, _ t: Data) -> Fr {
        Fr.hash([Data("atlas/ps-cred/v1".utf8), Data(pub.bytes()), t])
    }

    public static func present(_ pub: PublicKey, _ sig: Signature, messages: [Fr],
                               reveal: [Int], nonce: Data) -> Proof {
        let rev = reveal.sorted()
        let hidden = (0..<pub.n).filter { !rev.contains($0) }
        let r = Fr.random(), t = Fr.random()
        let s1 = sig.s1.mul(r)
        let s2 = sig.s2.mul(r) + s1.mul(t)

        // Commitment R in G2 = g2^{rhoT} · prod_hidden Y~_i^{rho_i}
        let rho = hidden.map { _ in Fr.random() }
        let rhoT = Fr.random()
        var Rc = G2.generator.mul(rhoT)
        for (i, rr) in zip(hidden, rho) { Rc = Rc + pub.Yt[i].mul(rr) }

        let vals = rev.map { messages[$0] }
        let c = challenge(pub, transcript(s1, s2, Rc, rev, vals, nonce))
        var responses = zip(hidden, rho).map { (i, rr) in rr + c * messages[i] }
        responses.append(rhoT + c * t)
        return Proof(s1: s1, s2: s2, commitment: Rc, reveal: rev, revealedVals: vals, responses: responses, challenge: c)
    }

    public static func verify(_ pub: PublicKey, _ proof: Proof, nonce: Data) -> Bool {
        guard proof.s1.isValid(), proof.s2.isValid() else { return false }
        let rev = proof.reveal
        guard Set(rev).count == rev.count, rev.allSatisfy({ $0 >= 0 && $0 < pub.n }) else { return false }
        let hidden = (0..<pub.n).filter { !rev.contains($0) }
        guard proof.responses.count == hidden.count + 1, proof.revealedVals.count == rev.count else { return false }
        let respHidden = Array(proof.responses.prefix(hidden.count))
        let respT = proof.responses[hidden.count]
        let c = proof.challenge

        // (1) Fiat-Shamir binds the sent commitment R (portable hash).
        let c2 = challenge(pub, transcript(proof.s1, proof.s2, proof.commitment, rev, proof.revealedVals, nonce))
        guard c2 == c else { return false }

        // (2) Pairing relation (representation-independent equality): e(s1,R) == e(s1,W) · target^{-c}.
        var kappaPub = pub.Xt
        for (i, m) in zip(rev, proof.revealedVals) { kappaPub = kappaPub + pub.Yt[i].mul(m) }
        let target = GT.pairing(proof.s2, G2.generator) * GT.pairing(proof.s1, kappaPub).inverse
        var W = G2.generator.mul(respT)
        for (i, s) in zip(hidden, respHidden) { W = W + pub.Yt[i].mul(s) }
        let lhs = GT.pairing(proof.s1, proof.commitment)
        let rhs = GT.pairing(proof.s1, W) * target.pow(c.negated)
        return lhs == rhs
    }
}
