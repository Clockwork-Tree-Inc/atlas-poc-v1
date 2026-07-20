import Foundation

/// Conversation state model over the forward-secret chain. Mirrors
/// `backend/atlas/session/conversation.py`. This is the state machine the
/// messaging UI sits on:
///
///   * ORDERING     — every message carries an index; the receiver tracks next-expected.
///   * OUT-OF-ORDER — a message ahead of earlier ones opens via a bounded skipped-
///                    message-key cache (Signal-style); earlier ones still open on arrival.
///   * REPLAY       — a consumed/unknown index is refused, fail-closed; MAX_SKIP guards DoS.
///   * PERSISTENCE  — the chain position serializes/restores so both sides resume in
///                    LOCKSTEP after an app restart; identity keys reload from the tree.
///   * MODE (per chat) — ACCOUNTABLE signs each message bound to (content, index,
///                    direction, epoch): non-repudiable. DENIABLE is symmetric-AEAD-auth
///                    only: a transcript proves neither party authored it.
///
/// FORWARD SECRECY (honest boundary): consumed message keys are discarded and the
/// chain key only advances forward, so a later state cannot derive an earlier
/// message key. Skipped-but-unconsumed keys are held in a BOUNDED cache (MAX_SKIP)
/// until their message arrives — the standard, bounded exposure.
public enum ConversationMode: String, Sendable {
    case accountable = "accountable"     // signed, non-repudiable
    case deniable = "deniable"           // symmetric-auth only -> deniable transcript
}

public enum ConversationError: Error {
    case replay(String)          // index already consumed or unknown
    case tooManySkipped(String)  // asked to skip more than MAX_SKIP
    case signatureRejected(String)
    case badMode(String)
    case badWire
}

public let MAX_SKIP = 256

enum ConvCore {
    /// Bind each ciphertext to its position so it cannot be replayed at another
    /// index/direction/epoch (the AEAD open fails if any differ).
    static func aad(direction: Data, index: Int, drandRound: Data) -> Data {
        Primitives.H(Data("atlas/conv/aad".utf8), direction, u64(index), drandRound)
    }
    /// The accountable signing core: binds WHO (via the signing key) to WHAT
    /// (content) at WHICH position (index/direction/epoch).
    static func sigCore(content: Data, direction: Data, index: Int, drandRound: Data) -> Data {
        Primitives.H(Data("atlas/conv/sig-core".utf8),
                     Primitives.H(Data("atlas/conv/content".utf8), content),
                     direction, u64(index), drandRound)
    }
    static func u64(_ i: Int) -> Data {
        var be = UInt64(i).bigEndian
        return withUnsafeBytes(of: &be) { Data($0) }
    }
}

/// One wire message. `signature` is present iff the chat is ACCOUNTABLE.
public struct Envelope: Sendable {
    public var index: Int
    public var direction: Data
    public var drandRound: Data
    public var ciphertext: Data
    public var signature: Data

    public init(index: Int, direction: Data, drandRound: Data, ciphertext: Data, signature: Data = Data()) {
        self.index = index; self.direction = direction; self.drandRound = drandRound
        self.ciphertext = ciphertext; self.signature = signature
    }

    public func toWire() -> Data {
        let obj: [String: Any] = [
            "i": index, "d": direction.base64EncodedString(), "e": drandRound.base64EncodedString(),
            "c": ciphertext.base64EncodedString(), "s": signature.base64EncodedString(),
        ]
        return (try? JSONSerialization.data(withJSONObject: obj)) ?? Data()
    }

    public static func fromWire(_ blob: Data) throws -> Envelope {
        guard let o = try JSONSerialization.jsonObject(with: blob) as? [String: Any],
              let i = o["i"] as? Int,
              let d = (o["d"] as? String).flatMap({ Data(base64Encoded: $0) }),
              let e = (o["e"] as? String).flatMap({ Data(base64Encoded: $0) }),
              let c = (o["c"] as? String).flatMap({ Data(base64Encoded: $0) }),
              let s = (o["s"] as? String).flatMap({ Data(base64Encoded: $0) }) else {
            throw ConversationError.badWire
        }
        return Envelope(index: i, direction: d, drandRound: e, ciphertext: c, signature: s)
    }
}

/// The sender's own direction: seal in sequence, index increments.
final class SendChain {
    private var ck: Data
    let drandRound: Data
    private let beaconT: Data
    private var i: Int

    init(ck: Data, drandRound: Data, beaconT: Data, index: Int = 0) {
        self.ck = ck; self.drandRound = drandRound; self.beaconT = beaconT; self.i = index
    }

    func seal(_ plaintext: Data, direction: Data) throws -> (index: Int, ct: Data) {
        let (mk, next) = FSConversation.step(ck, beaconT: beaconT, drandRound: drandRound)
        let index = i
        ck = next; i += 1                              // advance; old chain key discarded
        let ct = try Primitives.aeadEncrypt(key: mk, plaintext: plaintext,
                                            aad: ConvCore.aad(direction: direction, index: index, drandRound: drandRound))
        return (index, ct)
    }

    func snapshot() -> [String: Any] {
        ["ck": ck.base64EncodedString(), "epoch": drandRound.base64EncodedString(),
         "beacon": beaconT.base64EncodedString(), "i": i]
    }
    static func restore(_ s: [String: Any]) -> SendChain {
        SendChain(ck: Data(base64Encoded: s["ck"] as! String)!, drandRound: Data(base64Encoded: s["epoch"] as! String)!,
                  beaconT: Data(base64Encoded: s["beacon"] as! String)!, index: s["i"] as! Int)
    }
}

/// The peer's direction: open in order OR out of order via a bounded skipped
/// message-key cache; refuse replays.
final class RecvChain {
    private var ck: Data
    let drandRound: Data
    private let beaconT: Data
    private var next: Int
    private var skipped: [Int: Data]

    init(ck: Data, drandRound: Data, beaconT: Data, next: Int = 0, skipped: [Int: Data] = [:]) {
        self.ck = ck; self.drandRound = drandRound; self.beaconT = beaconT
        self.next = next; self.skipped = skipped
    }

    func open(index: Int, ciphertext: Data, direction: Data) throws -> Data {
        let mk: Data
        if index < next {
            guard let cached = skipped.removeValue(forKey: index) else {
                throw ConversationError.replay("message \(index) already consumed or unknown")
            }
            mk = cached
        } else {
            if index - next > MAX_SKIP {
                throw ConversationError.tooManySkipped("skip \(index - next) > \(MAX_SKIP)")
            }
            while next < index {                       // cache the skipped keys
                let (skmk, skn) = FSConversation.step(ck, beaconT: beaconT, drandRound: drandRound)
                skipped[next] = skmk
                ck = skn; next += 1
            }
            let (thismk, thisn) = FSConversation.step(ck, beaconT: beaconT, drandRound: drandRound)
            ck = thisn; next += 1                       // consume this index
            mk = thismk
        }
        return try Primitives.aeadDecrypt(key: mk, blob: ciphertext,
                                          aad: ConvCore.aad(direction: direction, index: index, drandRound: drandRound))
    }

    func snapshot() -> [String: Any] {
        var sk: [String: String] = [:]
        for (i, mk) in skipped { sk[String(i)] = mk.base64EncodedString() }
        return ["ck": ck.base64EncodedString(), "epoch": drandRound.base64EncodedString(),
                "beacon": beaconT.base64EncodedString(), "next": next, "skipped": sk]
    }
    static func restore(_ s: [String: Any]) -> RecvChain {
        var sk: [Int: Data] = [:]
        for (i, mk) in (s["skipped"] as! [String: String]) { sk[Int(i)!] = Data(base64Encoded: mk)! }
        return RecvChain(ck: Data(base64Encoded: s["ck"] as! String)!, drandRound: Data(base64Encoded: s["epoch"] as! String)!,
                         beaconT: Data(base64Encoded: s["beacon"] as! String)!, next: s["next"] as! Int, skipped: sk)
    }
}

/// One party's view of a two-party conversation: a send chain (my direction) and
/// a receive chain (the peer's direction), plus the per-chat mode.
///
/// Both parties derive the SAME per-direction seed from shared live material
/// (static KEM channel key + live co-derived LK + epoch), so A's send chain and
/// B's receive chain for the A->B direction are identical — lockstep with no
/// per-message secret transmitted.
public final class Conversation {
    public let mode: ConversationMode
    private let myDir: Data
    private let peerDir: Data
    private let send: SendChain
    private let recv: RecvChain
    private let authorship: Child?
    private let peerPublic: HybridSign.PublicKey?

    init(mode: ConversationMode, myDirection: Data, peerDirection: Data,
         send: SendChain, recv: RecvChain,
         authorship: Child?, peerPublic: HybridSign.PublicKey?) throws {
        if mode == .accountable && authorship == nil {
            throw ConversationError.badMode("ACCOUNTABLE chat requires the sender's authorship child")
        }
        self.mode = mode; self.myDir = myDirection; self.peerDir = peerDirection
        self.send = send; self.recv = recv
        self.authorship = authorship; self.peerPublic = peerPublic
    }

    public static func create(mode: ConversationMode, myDirection: Data, peerDirection: Data,
                              channelKey: Data, lk: Data, drandRound: Data, beaconT: Data,
                              authorship: Child? = nil, peerPublic: HybridSign.PublicKey? = nil) throws -> Conversation {
        let sSeed = FSConversation.seedChain(channelKey: channelKey, lk: lk, drandRound: drandRound, direction: myDirection)
        let rSeed = FSConversation.seedChain(channelKey: channelKey, lk: lk, drandRound: drandRound, direction: peerDirection)
        return try Conversation(mode: mode, myDirection: myDirection, peerDirection: peerDirection,
                                send: SendChain(ck: sSeed, drandRound: drandRound, beaconT: beaconT),
                                recv: RecvChain(ck: rSeed, drandRound: drandRound, beaconT: beaconT),
                                authorship: authorship, peerPublic: peerPublic)
    }

    public func send(_ plaintext: Data) throws -> Envelope {
        let (index, ct) = try send.seal(plaintext, direction: myDir)
        var sig = Data()
        if mode == .accountable {
            let core = ConvCore.sigCore(content: plaintext, direction: myDir, index: index, drandRound: send.drandRound)
            sig = try HybridSign.sign(authorship!.keypair, core)
        }
        return Envelope(index: index, direction: myDir, drandRound: send.drandRound, ciphertext: ct, signature: sig)
    }

    public func receive(_ env: Envelope) throws -> Data {
        let plaintext = try recv.open(index: env.index, ciphertext: env.ciphertext, direction: env.direction)
        if mode == .accountable {
            guard let pub = peerPublic else {
                throw ConversationError.signatureRejected("ACCOUNTABLE chat: no peer authorship public to verify against")
            }
            let core = ConvCore.sigCore(content: plaintext, direction: env.direction, index: env.index, drandRound: env.drandRound)
            if !HybridSign.verify(pub, core, env.signature) {
                throw ConversationError.signatureRejected("message \(env.index): authorship signature invalid")
            }
        }
        return plaintext
    }

    // -- persistence: chain position survives an app restart, keys reload from tree
    public func serialize() -> Data {
        let obj: [String: Any] = [
            "mode": mode.rawValue,
            "my_dir": myDir.base64EncodedString(), "peer_dir": peerDir.base64EncodedString(),
            "send": send.snapshot(), "recv": recv.snapshot(),
        ]
        return (try? JSONSerialization.data(withJSONObject: obj)) ?? Data()
    }

    public static func deserialize(_ blob: Data, authorship: Child? = nil,
                                   peerPublic: HybridSign.PublicKey? = nil) throws -> Conversation {
        guard let o = try JSONSerialization.jsonObject(with: blob) as? [String: Any],
              let modeRaw = o["mode"] as? String, let mode = ConversationMode(rawValue: modeRaw),
              let myD = (o["my_dir"] as? String).flatMap({ Data(base64Encoded: $0) }),
              let peerD = (o["peer_dir"] as? String).flatMap({ Data(base64Encoded: $0) }),
              let sendS = o["send"] as? [String: Any], let recvS = o["recv"] as? [String: Any] else {
            throw ConversationError.badWire
        }
        return try Conversation(mode: mode, myDirection: myD, peerDirection: peerD,
                                send: SendChain.restore(sendS), recv: RecvChain.restore(recvS),
                                authorship: authorship, peerPublic: peerPublic)
    }
}
