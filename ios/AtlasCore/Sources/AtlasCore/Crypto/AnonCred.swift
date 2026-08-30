import Foundation

/// High-level anonymous accreditation on blst — the master-secret model, on-device. Parity with
/// backend/atlas/realid/anon_accreditation.py: credentials bind to the System-ID root (the master
/// secret), shown in zero knowledge from any persona, with voluntary claim-jack-proof linking to an
/// identity you choose. Thin wrapper over PS (issue/present/verify) plus the linked showing.
public enum AnonCred {

    /// Your master secret (link secret) as a field element, derived from a secret seed (System-ID root
    /// for all personas, or a persona seed for a scoped credential).
    public static func masterSecret(_ seed: Data) -> Fr {
        Fr.hash([Data("atlas/anon-accred/master-secret/v1".utf8), seed])
    }

    public static func newIssuer() -> PS.SecretKey { PS.keygen(2) }   // [claim, master_secret]

    public static func issue(_ issuer: PS.SecretKey, claim: String, master: Fr) -> PS.Signature {
        PS.sign(issuer, messages: [Fr.msg(claim), master])
    }

    /// Anonymous showing from any persona: reveal the claim, hide the master secret.
    public static func present(_ pub: PS.PublicKey, _ cred: PS.Signature, claim: String, master: Fr,
                               nonce: Data) -> PS.Proof {
        PS.present(pub, cred, messages: [Fr.msg(claim), master], reveal: [0], nonce: nonce)
    }

    public static func verify(_ pub: PS.PublicKey, _ proof: PS.Proof, claim: String, nonce: Data) -> Bool {
        guard proof.reveal == [0], proof.revealedVals.count == 1, proof.revealedVals[0] == Fr.msg(claim) else {
            return false
        }
        return PS.verify(pub, proof, nonce: nonce)
    }

    // MARK: voluntary linked showing (claim under a persona / Real-ID you choose)

    private static func proofBytes(_ p: PS.Proof) -> Data {
        var d = Data(p.s1.serialize()); d.append(Data(p.s2.serialize()))
        for v in p.revealedVals { d.append(Data(v.bytesBE())) }
        for r in p.responses { d.append(Data(r.bytesBE())) }
        d.append(Data(p.challenge.bytesBE()))
        return d
    }

    private static func boundNonce(_ nonce: Data, _ identity: HybridSign.PublicKey) -> Data {
        Primitives.H(Data("atlas/anon-accred/link-nonce/v1".utf8), nonce, identity.encode())
    }

    private static func linkMessage(_ p: PS.Proof, _ claim: String, _ nonce: Data) -> Data {
        Primitives.H(Data("atlas/anon-accred/link/v1".utf8), proofBytes(p), Data(claim.utf8), nonce)
    }

    /// Attach the showing to an identity you control (claim an award under your Real-ID, surface a
    /// credential on a chosen face). Claim-jack-proof: the proof's nonce is bound to the identity.
    public static func presentLinked(_ pub: PS.PublicKey, _ cred: PS.Signature, claim: String, master: Fr,
                                     nonce: Data, identity: HybridSign.Keypair) throws
        -> (PS.Proof, HybridSign.PublicKey, Data) {
        let proof = present(pub, cred, claim: claim, master: master, nonce: boundNonce(nonce, identity.publicKey))
        let sig = try HybridSign.sign(identity, linkMessage(proof, claim, nonce))
        return (proof, identity.publicKey, sig)
    }

    public static func verifyLinked(_ pub: PS.PublicKey, _ proof: PS.Proof, claim: String, nonce: Data,
                                    identity: HybridSign.PublicKey, linkSig: Data) -> Bool {
        guard verify(pub, proof, claim: claim, nonce: boundNonce(nonce, identity)) else { return false }
        return HybridSign.verify(identity, linkMessage(proof, claim, nonce), linkSig)
    }
}
