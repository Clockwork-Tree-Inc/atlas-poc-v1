import Foundation

/// Revocable anonymous credentials on blst — one zero-knowledge showing that proves, together and
/// unlinkably, a valid credential for `claim` (hiding master secret + handle) AND that the same handle
/// is non-revoked. Parity with backend/atlas/realid/anon_revocable.py: the PS credential proof and the
/// accumulator membership proof share one Fiat-Shamir challenge and ONE handle response, so you can only
/// pass with your credential's own handle and its witness. Messages: [claim, master_secret, handle].
public enum Revocable {

    static let CLAIM = 0, MASTER = 1, HANDLE = 2

    public static func newIssuer() -> PS.SecretKey { PS.keygen(3) }

    public static func issue(_ issuer: PS.SecretKey, claim: String, master: Fr, handle: Fr) -> PS.Signature {
        PS.sign(issuer, messages: [Fr.msg(claim), master, handle])
    }

    public struct Proof: Sendable {
        public let s1: G1, s2: G1, wbar: G1
        public let rPs: G2, rMem: G1
        public let c: Fr, zMs: Fr, zHandle: Fr, zT: Fr, zRho: Fr
    }

    private static func transcript(_ pub: PS.PublicKey, _ s1: G1, _ s2: G1, _ wbar: G1,
                                   _ rPs: G2, _ rMem: G1, _ claim: String, _ nonce: Data) -> Fr {
        Fr.hash([Data("atlas/anon-revocable/v1".utf8), Data(pub.bytes()),
                 Data(s1.serialize()), Data(s2.serialize()), Data(wbar.serialize()),
                 Data(rPs.serialize()), Data(rMem.serialize()),
                 Data(Fr.msg(claim).bytesBE()), nonce])
    }

    public static func present(_ pub: PS.PublicKey, _ cred: PS.Signature, accPub: G2, accumulator: G1,
                               claim: String, master: Fr, handle: Fr, witness: G1, nonce: Data) -> Proof {
        let Yt = pub.Yt
        let r = Fr.random(), t = Fr.random()
        let s1 = cred.s1.mul(r)
        let s2 = cred.s2.mul(r) + s1.mul(t)
        let rho = Fr.random()
        let wbar = witness.mul(rho)

        let rhoMs = Fr.random(), kHandle = Fr.random(), rhoT = Fr.random(), kRho = Fr.random()
        // credential commitment R_ps (G2) = g2^{rhoT} * Y~_ms^{rhoMs} * Y~_handle^{kHandle}
        var rPs = G2.generator.mul(rhoT)
        rPs = rPs + Yt[MASTER].mul(rhoMs)
        rPs = rPs + Yt[HANDLE].mul(kHandle)
        // membership commitment R_mem (G1) = kHandle*wbar + kRho*Acc  (SAME kHandle -> binds the handle)
        let rMem = wbar.mul(kHandle) + accumulator.mul(kRho)
        let c = transcript(pub, s1, s2, wbar, rPs, rMem, claim, nonce)

        return Proof(s1: s1, s2: s2, wbar: wbar, rPs: rPs, rMem: rMem, c: c,
                     zMs: rhoMs + c * master,
                     zHandle: kHandle + c * handle,        // shared response
                     zT: rhoT + c * t,
                     zRho: kRho + c * rho.negated)
    }

    public static func verify(_ pub: PS.PublicKey, accPub: G2, accumulator: G1, _ proof: Proof,
                              claim: String, nonce: Data) -> Bool {
        guard proof.s1.isValid(), proof.s2.isValid(), proof.wbar.isValid(), proof.rMem.isValid(),
              accumulator.isValid(), proof.rPs.isValid() else { return false }
        let Yt = pub.Yt
        let c = proof.c
        guard transcript(pub, proof.s1, proof.s2, proof.wbar, proof.rPs, proof.rMem, claim, nonce) == c else {
            return false
        }

        // (1) credential: e(s1, R_ps) == e(s1, W_ps) * target^{-c}
        let kappa = pub.Xt + Yt[CLAIM].mul(Fr.msg(claim))
        let target = GT.pairing(proof.s2, G2.generator) * GT.pairing(proof.s1, kappa).inverse
        var wPs = G2.generator.mul(proof.zT)
        wPs = wPs + Yt[MASTER].mul(proof.zMs)
        wPs = wPs + Yt[HANDLE].mul(proof.zHandle)
        guard GT.pairing(proof.s1, proof.rPs) == GT.pairing(proof.s1, wPs) * target.pow(c.negated) else {
            return false
        }

        // (2) membership: e(R_mem, g2) == e(zHandle*wbar + zRho*Acc, g2) * e(c*wbar, P)
        let m = proof.wbar.mul(proof.zHandle) + accumulator.mul(proof.zRho)
        let n = proof.wbar.mul(c)
        return GT.pairing(proof.rMem, G2.generator) == GT.pairing(m, G2.generator) * GT.pairing(n, accPub)
    }
}
