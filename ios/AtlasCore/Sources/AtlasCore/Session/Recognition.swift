import Foundation
import CryptoKit

/// Recognition and the evolving tunnel (§4). Mirrors
/// `backend/atlas/session/recognition.py`.
///
/// recognition      = HKDF( SessionKey_1, SessionKey_2, beacon )
/// tunnel_key[next] = HKDF( tunnel_key[prev], recognition[this_epoch] )
///
/// Realisation: each device derives a per-epoch X25519 ephemeral keypair from
/// its OWN session key; the public halves are exchanged. The DH shared secret
/// stands in for the joint function of both session keys without either crossing
/// the wire. Symmetric ordering (§3.2 #2): contributions enter in sorted order.
public struct RecognitionContribution: Equatable {
    public let publicKey: Data   // raw X25519 public key
}

public enum Recognition {
    static func epochEphemeral(sessionKey: Data, beacon: Data) -> Curve25519.KeyAgreement.PrivateKey {
        let seed = Primitives.hkdf(ikm: sessionKey, info: Params.contextRecognition + Data("|eph|".utf8) + beacon, length: 32)
        return try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: seed)
    }

    public static func contribution(sessionKey: Data, beacon: Data)
        -> (priv: Curve25519.KeyAgreement.PrivateKey, pub: RecognitionContribution) {
        let priv = epochEphemeral(sessionKey: sessionKey, beacon: beacon)
        return (priv, RecognitionContribution(publicKey: priv.publicKey.rawRepresentation))
    }

    public static func value(myPriv: Curve25519.KeyAgreement.PrivateKey, theirPub: Data,
                             myPub: Data, beacon: Data) -> Data {
        let theirKey = try! Curve25519.KeyAgreement.PublicKey(rawRepresentation: theirPub)
        let shared = (try! myPriv.sharedSecretFromKeyAgreement(with: theirKey)).withUnsafeBytes { Data($0) }
        let pair = [myPub, theirPub].sorted { $0.lexicographicallyPrecedes($1) }
        return Primitives.hkdfCombine([shared, pair[0], pair[1], beacon], info: Params.contextRecognition, length: 32)
    }

    /// tunnel_key[next] = HKDF(tunnel_key[prev], recognition) (§4).
    public static func evolveTunnelKey(_ prev: Data, recognition: Data) -> Data {
        Primitives.hkdfCombine([prev, recognition], info: Params.contextTunnel, length: 32)
    }

    // MARK: Hybrid PQ recognition — ML-KEM-768 + X25519 (core tunnel is PQ)
    //
    // Mirrors backend/atlas/session/recognition.py. Symmetric two-encapsulation
    // handshake: each side derives its X25519 half from the session key and
    // generates an ephemeral ML-KEM keypair; each encapsulates to the other's
    // ML-KEM key; both exchange ciphertexts and decapsulate; the recognition
    // mixes the X25519 DH with BOTH ML-KEM shared secrets. Uses CryptoKit's
    // MLKEM768 (the flagged PQC seam — verify against the target SDK).

    public struct HybridContribution: Sendable {
        public let x25519Pub: Data
        public let mlkemEK: Data
    }

    public static func hybridContribution(sessionKey: Data, beacon: Data)
        -> (xPriv: Curve25519.KeyAgreement.PrivateKey, mlkemSK: MLKEM768.PrivateKey, pub: HybridContribution) {
        let xPriv = epochEphemeral(sessionKey: sessionKey, beacon: beacon)
        let mlkem = try! MLKEM768.PrivateKey()   // random keygen; throws only catastrophically
        return (xPriv, mlkem,
                HybridContribution(x25519Pub: xPriv.publicKey.rawRepresentation,
                                   mlkemEK: mlkem.publicKey.rawRepresentation))
    }

    public static func hybridEncapsulate(_ their: HybridContribution) throws -> (ct: Data, ss: Data) {
        let ek = try MLKEM768.PublicKey(rawRepresentation: their.mlkemEK)
        let r = try ek.encapsulate()
        return (r.encapsulated, r.sharedSecret.withUnsafeBytes { Data($0) })
    }

    public static func hybridRecognitionValue(
        myXPriv: Curve25519.KeyAgreement.PrivateKey, myMlkemSK: MLKEM768.PrivateKey,
        myPub: HybridContribution, theirPub: HybridContribution, theirCT: Data,
        mySSself: Data, beacon: Data) throws -> Data {
        let theirX = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: theirPub.x25519Pub)
        let xDH = (try myXPriv.sharedSecretFromKeyAgreement(with: theirX)).withUnsafeBytes { Data($0) }
        let ssPeer = try myMlkemSK.decapsulate(theirCT).withUnsafeBytes { Data($0) }
        let ss = [mySSself, ssPeer].sorted { $0.lexicographicallyPrecedes($1) }
        let pubs = [myPub.x25519Pub, theirPub.x25519Pub].sorted { $0.lexicographicallyPrecedes($1) }
        return Primitives.hkdfCombine([xDH, ss[0], ss[1], pubs[0], pubs[1], beacon],
                                      info: Params.contextRecognition + Data("/hybrid".utf8), length: 32)
    }
}

private extension Data {
    func lexicographicallyPrecedes(_ other: Data) -> Bool {
        for (a, b) in zip(self, other) { if a != b { return a < b } }
        return count < other.count
    }
}
