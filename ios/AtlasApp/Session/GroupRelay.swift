import Foundation
import AtlasCore

/// N-user group session over the blind Mac node. Any number of NAMED users join
/// (2 is the minimum to go live). Peers are discovered from the node roster
/// (`/status`); each pair sets up a KEM channel; every user contributes ONE fresh
/// LK secret; and everyone co-derives the SAME group LK from all contributions
/// (`LiveLK.coDeriveLK`, order-independent). Messages are sealed under a key derived
/// from the group LK and broadcast to each member — the node relays opaque bytes and
/// stays blind. The LK never leaves this object.
///
/// Honest boundary: group messages are group-LK-sealed (not the per-message
/// forward-secret double chain the 1:1 `Conversation` gives) — fine for the N-phone
/// test surface; a group ratchet is the documented next step.
@MainActor
final class GroupRelay {

    private let baseURL: URL
    let me: String
    private let authorship: Child
    private let drandRound: Data
    private let myKEM = HybridKEM.generateKeypair()
    private let myContribution = LiveLK.deviceContribution()   // ONE, shared to all peers

    private var channels: [String: Data] = [:]        // peer -> shared KEM key
    private var contributions: [String: Data] = [:]   // peer -> their LK contribution
    private var peerAuth: [String: Data] = [:]        // peer -> verified authorship public key (encoded)
    private var verifiedKEM: [String: HybridKEM.PublicKey] = [:]  // peer -> its identity-bound KEM key
    private(set) var roster: [String] = []
    private(set) var groupLK: Data?

    var onRoster: (([String]) -> Void)?
    var onLK: ((Data?) -> Void)?
    var onMessage: ((String, String) -> Void)?
    var onStatus: ((String) -> Void)?        // connection state / errors for the UI log
    var onSafetyNumber: ((String) -> Void)?  // OOB fingerprint of the verified member identity keys
    private var lastStatus = ""
    private var lastSafety = ""

    // The identity-binding message a member signs over its KEM public key, so the blind
    // node cannot swap in its own KEM key without also forging this member's signature.
    private static let bindLabel = Data("atlas/group-kem-bind".utf8)
    private func bindMessage(name: String, mlkemEK: Data, x25519PK: Data) -> Data {
        Primitives.H(GroupRelay.bindLabel, Data(name.utf8), mlkemEK, x25519PK, drandRound)
    }

    private let http = URLSession(configuration: .ephemeral)
    private var loop: Task<Void, Never>?

    private static let kemP = Data("KEMCT:".utf8)
    private static let conP = Data("CONTRIB:".utf8)
    private static let msgP = Data("MSG:".utf8)
    enum Err: Error { case badPeer, http(Int) }

    init(baseURL: URL, me: String, authorship: Child, drandRound: Data) {
        self.baseURL = baseURL; self.me = me; self.authorship = authorship; self.drandRound = drandRound
    }

    func start() {
        loop?.cancel()
        loop = Task { [weak self] in
            guard let self else { return }
            do { try await self.register(); self.report("registered at node as \(self.me)") }
            catch { self.report("cannot reach node: \(Self.explain(error))") }
            while !Task.isCancelled {
                await self.tick()
                try? await Task.sleep(nanoseconds: 1_500_000_000)
            }
        }
    }
    func stop() { loop?.cancel(); loop = nil }

    /// Emit a status line to the UI, de-duped so the log isn't spammed every tick.
    private func report(_ s: String) {
        guard s != lastStatus else { return }
        lastStatus = s; onStatus?(s)
    }

    /// Turn a URLError into plain language — the common two-phone blockers.
    private static func explain(_ error: Error) -> String {
        guard let u = error as? URLError else { return "\(error)" }
        switch u.code {
        case .timedOut: return "timed out — is the node running + on the same Wi-Fi? Allow ‘Local Network’ for Atlas in iOS Settings."
        case .cannotConnectToHost, .cannotFindHost: return "can’t connect — check the node URL / that the node is running."
        case .networkConnectionLost, .notConnectedToInternet: return "network lost — same Wi-Fi? Local Network permission on?"
        default: return u.localizedDescription
        }
    }

    private func register() async throws {
        let pub = myKEM.publicKey
        let apub = authorship.publicKey
        // Bind my KEM public key to my identity: sign it with my authorship key. The blind
        // node relays this opaquely (it never inspects kem_pub), so it cannot swap in its
        // own KEM key without ALSO forging my signature.
        let sig = try HybridSign.sign(authorship.keypair,
                                      bindMessage(name: me, mlkemEK: pub.mlkemEK, x25519PK: pub.x25519PK))
        _ = try await post("relay/register", ["mailbox": me,
            "kem_pub": [
                "mlkemEK": pub.mlkemEK.base64EncodedString(),
                "x25519PK": pub.x25519PK.base64EncodedString(),
                "auth_mldsa": apub.mldsaPK.base64EncodedString(),
                "auth_ed": apub.edPK.base64EncodedString(),
                "bind_sig": sig.base64EncodedString(),
            ]])
    }

    private func tick() async {
        do {
            let r = try await fetchRoster()
            report(r.isEmpty ? "online — no other members yet" : "node sees: \(r.joined(separator: ", "))")
            if r != roster { roster = r; onRoster?(r) }
            for p in r {
                // Verify EVERY member's identity-bound KEM key (needed for the safety
                // number), then open a channel only where we're the deterministic initiator.
                if verifiedKEM[p] == nil, let (kemPub, authEnc) = try? await verifyPeer(p) {
                    verifiedKEM[p] = kemPub; peerAuth[p] = authEnc
                    updateSafetyNumber()
                }
                if channels[p] == nil, me < p, let kemPub = verifiedKEM[p] {   // lower name encapsulates
                    if let key = try? await openChannel(to: p, kemPub: kemPub) {
                        channels[p] = key
                        try? await sendContribution(to: p, key: key)
                    }
                }
            }
        } catch {
            report("node unreachable: \(Self.explain(error))")
        }
        if let inbox = try? await fetchInbox() {
            for (frm, blob) in inbox { await handle(frm: frm, blob: blob) }
        }
        rederiveLK()
    }

    private func fetchRoster() async throws -> [String] {
        let data = try await get("status")
        guard let o = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let mbs = o["mailboxes"] as? [[String: Any]] else { return [] }
        return mbs.compactMap { $0["mid"] as? String }.filter { $0 != me }.sorted()
    }

    /// Fetch a peer's registered KEM key + identity binding and VERIFY the signature
    /// under the claimed authorship key. Rejects (throws) if the binding is invalid — the
    /// node cannot present a KEM key that isn't signed by some identity. Returns the KEM
    /// key + the encoded authorship key (for the safety number).
    private func verifyPeer(_ peer: String) async throws -> (HybridKEM.PublicKey, Data) {
        let data = try await get("relay/pubkey/\(peer)")
        guard let o = try JSONSerialization.jsonObject(with: data) as? [String: String],
              let ek = o["mlkemEK"].flatMap({ Data(base64Encoded: $0) }),
              let xpk = o["x25519PK"].flatMap({ Data(base64Encoded: $0) }),
              let am = o["auth_mldsa"].flatMap({ Data(base64Encoded: $0) }),
              let ae = o["auth_ed"].flatMap({ Data(base64Encoded: $0) }),
              let sig = o["bind_sig"].flatMap({ Data(base64Encoded: $0) }) else { throw Err.badPeer }
        let apub = HybridSign.PublicKey(mldsaPK: am, edPK: ae)
        guard HybridSign.verify(apub, bindMessage(name: peer, mlkemEK: ek, x25519PK: xpk), sig) else {
            report("⚠️ \(peer): identity signature INVALID — refusing (possible MITM at the relay).")
            throw Err.badPeer
        }
        report("verified \(peer)’s identity binding ✓")
        return (HybridKEM.PublicKey(mlkemEK: ek, x25519PK: xpk), apub.encode())
    }

    private func openChannel(to peer: String, kemPub: HybridKEM.PublicKey) async throws -> Data {
        let enc = try HybridKEM.encapsulate(to: kemPub)   // to the IDENTITY-VERIFIED key
        var blob = GroupRelay.kemP
        var len = UInt32(enc.mlkemCT.count).bigEndian
        withUnsafeBytes(of: &len) { blob.append(contentsOf: $0) }
        blob.append(enc.mlkemCT); blob.append(enc.x25519EphPK)
        try await relay(to: peer, blob: blob)
        return enc.shared
    }

    /// A short fingerprint of the SORTED set of verified member identity keys (mine +
    /// every verified peer's). Two honest members compute the SAME number; a relay that
    /// substitutes any member's identity key makes them DIFFER — so members compare it
    /// out-of-band (read it aloud) to detect a man-in-the-middle. (Signal's "safety number".)
    private func updateSafetyNumber() {
        let keys = ([authorship.publicKey.encode()] + peerAuth.values)
            .sorted { $0.lexicographicallyPrecedes($1) }
        let fp = Primitives.H(Data("atlas/safety-number".utf8), keys.reduce(Data(), +))
        var groups: [String] = []
        for i in 0..<6 {
            let v = (UInt32(fp[2 * i]) << 8 | UInt32(fp[2 * i + 1])) % 100000
            groups.append(String(format: "%05u", v))
        }
        let formatted = groups.joined(separator: " ")
        if formatted != lastSafety { lastSafety = formatted; onSafetyNumber?(formatted) }
    }

    private func sendContribution(to peer: String, key: Data) async throws {
        let sealed = try Tunnel.sealNormalBlob(myContribution, key: key)
        try await relay(to: peer, blob: GroupRelay.conP + sealed)
    }

    private func handle(frm: String, blob: Data) async {
        if blob.starts(with: GroupRelay.kemP) {
            let rest = Data(blob.dropFirst(GroupRelay.kemP.count))
            guard rest.count >= 4 else { return }
            let ctLen = rest.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
            let body = Data(rest.dropFirst(4))
            guard body.count >= ctLen else { return }
            let ct = Data(body.prefix(ctLen)), eph = Data(body.dropFirst(ctLen))
            if let key = try? HybridKEM.decapsulate(myKEM, mlkemCT: ct, x25519EphPK: eph) {
                channels[frm] = key
                try? await sendContribution(to: frm, key: key)   // respond with our contribution
            }
        } else if blob.starts(with: GroupRelay.conP) {
            guard let key = channels[frm] else { return }
            if let c = try? Tunnel.openNormalBlob(Data(blob.dropFirst(GroupRelay.conP.count)), key: key) {
                contributions[frm] = c
            }
        } else if blob.starts(with: GroupRelay.msgP) {
            guard let lk = groupLK else { return }
            if let pt = try? Tunnel.openNormalBlob(Data(blob.dropFirst(GroupRelay.msgP.count)), key: msgKey(lk)) {
                onMessage?(frm, String(decoding: pt, as: UTF8.self))
            }
        }
    }

    private func rederiveLK() {
        guard !contributions.isEmpty else { if groupLK != nil { groupLK = nil; onLK?(nil) }; return }
        let all = [myContribution] + Array(contributions.values)
        if let lk = try? LiveLK.coDeriveLK(all, drandRound: drandRound), lk != groupLK {
            groupLK = lk; onLK?(lk)
        }
    }

    func send(_ text: String) {
        guard let lk = groupLK else { return }
        let peers = Array(channels.keys)
        Task {
            guard let sealed = try? Tunnel.sealNormalBlob(Data(text.utf8), key: msgKey(lk)) else { return }
            for p in peers { try? await relay(to: p, blob: GroupRelay.msgP + sealed) }
        }
    }

    private func msgKey(_ lk: Data) -> Data { Primitives.H(Data("atlas/group-msg".utf8), lk) }

    // transport
    private func relay(to peer: String, blob: Data) async throws {
        _ = try await post("relay/send", ["from": me, "to": peer, "blob": blob.base64EncodedString()])
    }
    private func fetchInbox() async throws -> [(String, Data)] {
        let data = try await get("relay/fetch/\(me)")
        guard let o = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let ms = o["messages"] as? [[String: Any]] else { return [] }
        return ms.compactMap { m in
            guard let f = m["frm"] as? String,
                  let b = (m["blob"] as? String).flatMap({ Data(base64Encoded: $0) }) else { return nil }
            return (f, b)
        }
    }
    private func get(_ path: String) async throws -> Data {
        let (d, r) = try await http.data(from: baseURL.appendingPathComponent(path)); try check(r); return d
    }
    private func post(_ path: String, _ body: [String: Any]) async throws -> Data {
        var req = URLRequest(url: baseURL.appendingPathComponent(path)); req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (d, r) = try await http.data(for: req); try check(r); return d
    }
    private func check(_ r: URLResponse) throws {
        guard let h = r as? HTTPURLResponse, (200..<300).contains(h.statusCode) else {
            throw Err.http((r as? HTTPURLResponse)?.statusCode ?? -1)
        }
    }
}
