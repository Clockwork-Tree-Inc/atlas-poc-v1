import Foundation
import AtlasCore

/// Forward-secret two-phone relay client — the phone side of the live-LK run.
///
/// This is the wiring that turns the Python reference (full-engine integration
/// test: co-derive LK + FS `Conversation` over the blind node) into a real run on
/// two iPhones through the Mac node:
///
///   1. register        — publish our mailbox + hybrid-KEM public key.
///   2. open channel     — KEM-encapsulate to the peer -> a shared A-B key the node
///                        never holds; relay the KEM ciphertext (opaque) to the peer.
///   3. LIVE LK          — each phone draws a fresh `LiveLK.deviceContribution()` and
///                        exchanges it SEALED under the A-B key (node blind). Each
///                        side `coDeriveLK([mine, theirs])` -> the IDENTICAL epoch LK,
///                        unpredictable-to-either, controllable-by-neither. The stub
///                        LK is gone.
///   4. FS conversation  — both build a `Conversation` seeded from (A-B channel key +
///                        co-derived LK + epoch). Messages seal under the RATCHETED
///                        key; the whole envelope is additionally sealed under the
///                        A-B key so the node relays FULLY OPAQUE bytes.
///
/// The node sees only envelope metadata (from/to mailbox, size, order). Content and
/// the LK are end-to-end; the node stays blind (mirrors the node-blindness assertion
/// in the reference test).
///
/// STATUS: SOURCE ONLY — runs on a device against a running Mac node
/// (`python -m atlas.net.node_server --host 0.0.0.0 --port 8787`). Not built/run in
/// the cloud env. See docs/TWO_PHONE_LIVE_LK_RUN.md for the end-to-end steps.
///
/// Isolation: `@MainActor` — driven directly by `MessagingModel` (also
/// `@MainActor`), so co-isolating them keeps the non-Sendable client and its
/// per-peer key/conversation state on one actor with nothing crossing a boundary.
/// The network I/O still suspends off-main inside `URLSession`'s `async` calls.
@MainActor
public final class FSRelayClient {

    public enum FSRelayError: Error { case http(Int), badResponse, noPeerKey, noABKey, noLK, noConversation }

    // wire framing prefixes (the node never interprets these — they are inside the blob)
    private static let kemPrefix = Data("KEMCT:".utf8)
    private static let contribPrefix = Data("CONTRIB:".utf8)
    private static let msgPrefix = Data("MSG:".utf8)

    private let baseURL: URL
    public let mailbox: String
    private let myKEM: HybridKEM.Keypair
    private let authorship: Child
    private let peerPublic: HybridSign.PublicKey?
    private let mode: ConversationMode
    private let urlSession = URLSession(configuration: .ephemeral)

    private var abKeys: [String: Data] = [:]          // peer -> shared A-B key
    private var myContribution: [String: Data] = [:]  // peer -> our fresh LK half (per peer)
    private var epoch: [String: Data] = [:]           // peer -> agreed epoch id
    private var beaconT: [String: Data] = [:]         // peer -> agreed beacon material
    private var liveLK: [String: Data] = [:]          // peer -> co-derived LK (display/telemetry)
    private var convo: [String: Conversation] = [:]   // peer -> FS conversation

    public private(set) var lastStatus = "idle"

    public init(baseURL: URL, mailbox: String, authorship: Child,
                peerPublic: HybridSign.PublicKey? = nil, mode: ConversationMode = .accountable) {
        self.baseURL = baseURL
        self.mailbox = mailbox
        self.myKEM = HybridKEM.generateKeypair()
        self.authorship = authorship
        self.peerPublic = peerPublic
        self.mode = mode
    }

    /// The co-derived LK for a peer, once the exchange has completed (for the UI to
    /// show "live LK established" — a prefix only, never the whole key).
    public func liveLKEstablished(with peer: String) -> Data? { liveLK[peer] }

    // MARK: - 1. register

    public func register() async throws {
        let pub = myKEM.publicKey
        _ = try await post("relay/register", body: [
            "mailbox": mailbox,
            "kem_pub": ["mlkemEK": pub.mlkemEK.base64EncodedString(),
                        "x25519PK": pub.x25519PK.base64EncodedString()],
        ])
        lastStatus = "registered as \(mailbox)"
    }

    // MARK: - 2 + 3. open channel and kick off the live-LK exchange (INITIATOR side)

    /// A side: fetch the peer's KEM public, encapsulate (-> A-B key), relay the KEM
    /// ciphertext, then send our sealed LK contribution with an agreed epoch/beacon.
    public func beginLiveLK(with peer: String) async throws {
        let data = try await get("relay/pubkey/\(peer)")
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: String],
              let ek = obj["mlkemEK"].flatMap({ Data(base64Encoded: $0) }),
              let xpk = obj["x25519PK"].flatMap({ Data(base64Encoded: $0) }) else {
            throw FSRelayError.noPeerKey
        }
        let enc = try HybridKEM.encapsulate(to: HybridKEM.PublicKey(mlkemEK: ek, x25519PK: xpk))
        abKeys[peer] = enc.shared
        // relay the KEM ciphertext so the peer derives the SAME A-B key.
        // LENGTH-PREFIXED framing: the ML-KEM ciphertext is ~1KB of BINARY and can
        // contain any byte (including '|'/0x7C), so a byte separator would split in
        // the wrong place. Prefix the CT with its 4-byte big-endian length; the
        // remainder of the blob is the x25519 ephemeral public key.
        var kemBlob = FSRelayClient.kemPrefix
        var ctLen = UInt32(enc.mlkemCT.count).bigEndian
        withUnsafeBytes(of: &ctLen) { kemBlob.append(contentsOf: $0) }
        kemBlob.append(enc.mlkemCT)
        kemBlob.append(enc.x25519EphPK)
        try await relay(to: peer, blob: kemBlob)
        // initiator PICKS the public coordination values (epoch + beacon); the LK
        // VALUE itself is co-derived from both secret halves, so this is not control.
        let ep = Primitives.randomBytes(8)
        let bt = Primitives.randomBytes(16)
        epoch[peer] = ep; beaconT[peer] = bt
        try await sendContribution(to: peer)
        lastStatus = "channel + LK exchange started with \(peer)"
    }

    private func sendContribution(to peer: String) async throws {
        guard let ab = abKeys[peer], let ep = epoch[peer], let bt = beaconT[peer] else { throw FSRelayError.noABKey }
        let mine = myContribution[peer] ?? LiveLK.deviceContribution()
        myContribution[peer] = mine
        let payload: [String: String] = ["epoch": ep.base64EncodedString(), "beacon": bt.base64EncodedString(),
                                         "contrib": mine.base64EncodedString()]
        let sealed = try Tunnel.sealNormalBlob(try JSONSerialization.data(withJSONObject: payload), key: ab)
        try await relay(to: peer, blob: FSRelayClient.contribPrefix + sealed)
    }

    // MARK: - 4. send a forward-secret message

    public func send(_ text: String, to peer: String) async throws {
        guard let ab = abKeys[peer] else { throw FSRelayError.noABKey }
        guard let c = convo[peer] else { throw FSRelayError.noConversation }
        let env = try c.send(Data(text.utf8))
        // seal the whole envelope under the A-B key -> node relays fully opaque bytes.
        let sealed = try Tunnel.sealNormalBlob(env.toWire(), key: ab)
        try await relay(to: peer, blob: FSRelayClient.msgPrefix + sealed)
    }

    // MARK: - poll: process KEMCT / CONTRIB / MSG and return decrypted texts

    @discardableResult
    public func poll() async throws -> [(from: String, text: String)] {
        let data = try await get("relay/fetch/\(mailbox)")
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let msgs = obj["messages"] as? [[String: Any]] else { throw FSRelayError.badResponse }
        var out: [(from: String, text: String)] = []
        for m in msgs {
            guard let frm = m["frm"] as? String ?? m["from"] as? String,
                  let blobB64 = m["blob"] as? String, let blob = Data(base64Encoded: blobB64) else { continue }

            if blob.starts(with: FSRelayClient.kemPrefix) {
                try? acceptChannel(from: frm, kemBlob: blob)          // B derives the A-B key
                // B side is the RESPONDER: it must send ITS contribution back once it
                // learns epoch/beacon (which arrive in the CONTRIB message), so nothing
                // to send yet here.
            } else if blob.starts(with: FSRelayClient.contribPrefix) {
                try await handleContribution(from: frm, blob: blob)
            } else if blob.starts(with: FSRelayClient.msgPrefix) {
                if let text = try? handleMessage(from: frm, blob: blob) { out.append((from: frm, text: text)) }
            }
        }
        return out
    }

    private func acceptChannel(from peer: String, kemBlob: Data) throws {
        // Mirror the length-prefixed framing from beginLiveLK: [4-byte BE CT length]
        // [mlkemCT][x25519EphPK]. Re-base to 0 so slicing is index-safe.
        let rest = Data(kemBlob.dropFirst(FSRelayClient.kemPrefix.count))
        guard rest.count >= 4 else { throw FSRelayError.badResponse }
        let ctLen = rest.prefix(4).reduce(0) { ($0 << 8) | Int($1) }   // big-endian UInt32
        let body = Data(rest.dropFirst(4))
        guard body.count >= ctLen else { throw FSRelayError.badResponse }
        let mlkemCT = Data(body.prefix(ctLen))
        let ephPK = Data(body.dropFirst(ctLen))
        abKeys[peer] = try HybridKEM.decapsulate(myKEM, mlkemCT: mlkemCT, x25519EphPK: ephPK)
    }

    private func handleContribution(from peer: String, blob: Data) async throws {
        guard let ab = abKeys[peer] else { throw FSRelayError.noABKey }
        let sealed = Data(blob.dropFirst(FSRelayClient.contribPrefix.count))
        let json = try Tunnel.openNormalBlob(sealed, key: ab)
        guard let o = try JSONSerialization.jsonObject(with: json) as? [String: String],
              let ep = o["epoch"].flatMap({ Data(base64Encoded: $0) }),
              let bt = o["beacon"].flatMap({ Data(base64Encoded: $0) }),
              let theirs = o["contrib"].flatMap({ Data(base64Encoded: $0) }) else { throw FSRelayError.badResponse }

        let firstTime = (epoch[peer] == nil)
        epoch[peer] = ep; beaconT[peer] = bt                     // adopt the agreed coordination values
        // co-derive the IDENTICAL LK from both fresh secret halves.
        let mine = myContribution[peer] ?? LiveLK.deviceContribution()
        myContribution[peer] = mine
        let lk = try LiveLK.coDeriveLK([mine, theirs], drandRound: ep)
        liveLK[peer] = lk
        // build the FS conversation from (A-B channel key + co-derived LK + epoch).
        // direction is fixed by mailbox ordering so both sides agree on chains.
        let (myDir, peerDir) = directions(me: mailbox, peer: peer)
        convo[peer] = try Conversation.create(mode: mode, myDirection: myDir, peerDirection: peerDir,
                                              channelKey: ab, lk: lk, drandRound: ep, beaconT: bt,
                                              authorship: authorship, peerPublic: peerPublic)
        lastStatus = "live LK co-derived with \(peer) (\(lk.prefix(4).map { String(format: "%02x", $0) }.joined())…)"
        // RESPONDER: if we hadn't yet sent our half (we learned epoch/beacon just now), send it back.
        if firstTime { try await sendContribution(to: peer) }
    }

    private func handleMessage(from peer: String, blob: Data) throws -> String {
        guard let ab = abKeys[peer] else { throw FSRelayError.noABKey }
        guard let c = convo[peer] else { throw FSRelayError.noConversation }
        let sealed = Data(blob.dropFirst(FSRelayClient.msgPrefix.count))
        let wire = try Tunnel.openNormalBlob(sealed, key: ab)
        let env = try Envelope.fromWire(wire)
        return String(decoding: try c.receive(env), as: UTF8.self)
    }

    /// Deterministic direction labels so A's send chain == B's receive chain for a
    /// given ordered pair (lexicographically smaller mailbox is the "left").
    private func directions(me: String, peer: String) -> (mine: Data, peer: Data) {
        let (lo, hi) = me < peer ? (me, peer) : (peer, me)
        let l2r = Data("\(lo)->\(hi)".utf8), r2l = Data("\(hi)->\(lo)".utf8)
        return me == lo ? (l2r, r2l) : (r2l, l2r)
    }

    // MARK: - transport

    private func relay(to peer: String, blob: Data) async throws {
        _ = try await post("relay/send", body: ["from": mailbox, "to": peer, "blob": blob.base64EncodedString()])
    }
    private func get(_ path: String) async throws -> Data {
        let (data, resp) = try await urlSession.data(from: baseURL.appendingPathComponent(path))
        try check(resp); return data
    }
    private func post(_ path: String, body: [String: Any]) async throws -> Data {
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, resp) = try await urlSession.data(for: req)
        try check(resp); return data
    }
    private func check(_ resp: URLResponse) throws {
        guard let http = resp as? HTTPURLResponse else { throw FSRelayError.badResponse }
        guard (200..<300).contains(http.statusCode) else { throw FSRelayError.http(http.statusCode) }
    }
}
