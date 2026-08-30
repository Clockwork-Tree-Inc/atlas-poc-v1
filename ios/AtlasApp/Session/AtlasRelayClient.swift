import Foundation
import AtlasCore

/// Phone-side BLIND-RELAY client — end-to-end messaging where the Mac node NEVER
/// sees the content. Mirrors `backend/atlas/net/node_server.py`.
///
/// The two phones share an A-B key the node never holds:
///   1. B registers its hybrid-KEM public key (POST /relay/register).
///   2. A fetches B's public key (GET /relay/pubkey/B), encapsulates to it
///      (ML-KEM-768 + X25519) → a shared secret only A and B can derive, and
///      relays the KEM ciphertext to B (opaque to the node).
///   3. A seals each message/photo under the A-B key (`Tunnel.seal`) and relays
///      the OPAQUE blob (POST /relay/send). The node stores & forwards it; it
///      CANNOT open it. B fetches (GET /relay/fetch/B) and decrypts locally.
///
/// HONEST BOUNDARY: content is end-to-end (the node is blind to it); the node
/// still sees ENVELOPE METADATA (from/to mailbox, size, order). Sealed-sender /
/// mixing / cover-traffic is the upgrade path, not built here.
///
/// STATUS: unrun until built on a Mac to a device against a running node.
public final class AtlasRelayClient {

    public enum RelayError: Error { case http(Int), badResponse, noPeerKey, noABKey }

    private let baseURL: URL
    private let mailbox: String
    private let myKEM: HybridKEM.Keypair
    private var abKeys: [String: Data] = [:]        // peer mailbox -> shared A-B key
    private let session = URLSession(configuration: .ephemeral)

    public init(baseURL: URL, mailbox: String) {
        self.baseURL = baseURL
        self.mailbox = mailbox
        self.myKEM = HybridKEM.generateKeypair()
    }

    /// Publish our mailbox + PUBLIC key so peers can encapsulate to us.
    public func register() async throws {
        let pub = myKEM.publicKey
        _ = try await post("relay/register", body: [
            "mailbox": mailbox,
            "kem_pub": ["mlkemEK": pub.mlkemEK.base64EncodedString(),
                        "x25519PK": pub.x25519PK.base64EncodedString()],
        ])
    }

    /// Establish an A-B key with `peer` (A side): fetch peer's public key,
    /// encapsulate, relay the KEM ciphertext to the peer. The node cannot derive
    /// the resulting shared secret.
    public func openChannel(to peer: String) async throws {
        let data = try await get("relay/pubkey/\(peer)")
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: String],
              let ek = obj["mlkemEK"].flatMap({ Data(base64Encoded: $0) }),
              let xpk = obj["x25519PK"].flatMap({ Data(base64Encoded: $0) }) else {
            throw RelayError.noPeerKey
        }
        let enc = try HybridKEM.encapsulate(to: HybridKEM.PublicKey(mlkemEK: ek, x25519PK: xpk))
        abKeys[peer] = enc.shared
        // relay the KEM ciphertext to the peer so B derives the SAME key.
        let ctBlob = Data("KEMCT:".utf8) + enc.mlkemCT + Data("|".utf8) + enc.x25519EphPK
        try await relaySend(to: peer, blob: ctBlob)
    }

    /// Complete an A-B key from a received KEM ciphertext (B side).
    public func acceptChannel(from peer: String, kemBlob: Data) throws {
        // parse "KEMCT:<mlkemCT>|<ephPK>"
        let prefix = Data("KEMCT:".utf8)
        guard kemBlob.starts(with: prefix) else { throw RelayError.badResponse }
        let rest = kemBlob.dropFirst(prefix.count)
        guard let sep = rest.firstIndex(of: 0x7C) else { throw RelayError.badResponse }  // '|'
        let mlkemCT = Data(rest[rest.startIndex..<sep])
        let ephPK = Data(rest[rest.index(after: sep)...])
        abKeys[peer] = try HybridKEM.decapsulate(myKEM, mlkemCT: mlkemCT, x25519EphPK: ephPK)
    }

    /// Seal a message under the A-B key and relay the OPAQUE blob. The node cannot
    /// read it.
    public func sendMessage(_ text: String, to peer: String) async throws {
        guard let key = abKeys[peer] else { throw RelayError.noABKey }
        let blob = try Tunnel.sealNormalBlob(Data(text.utf8), key: key)
        try await relaySend(to: peer, blob: blob)
    }

    /// Fetch pending blobs, decrypt those we have an A-B key for, and hand back the
    /// (peer, plaintext) pairs. KEM-ciphertext envelopes are consumed to complete
    /// pending channels.
    public func fetch() async throws -> [(from: String, text: String)] {
        let data = try await get("relay/fetch/\(mailbox)")
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let msgs = obj["messages"] as? [[String: Any]] else { throw RelayError.badResponse }
        var out: [(from: String, text: String)] = []
        for m in msgs {
            guard let frm = m["from"] as? String,
                  let blobB64 = m["blob"] as? String, let blob = Data(base64Encoded: blobB64) else { continue }
            if blob.starts(with: Data("KEMCT:".utf8)) {
                try? acceptChannel(from: frm, kemBlob: blob)      // complete the A-B key
                continue
            }
            if let key = abKeys[frm], let pt = try? Tunnel.openNormalBlob(blob, key: key) {
                out.append((from: frm, text: String(decoding: pt, as: UTF8.self)))
            }
        }
        return out
    }

    // MARK: - transport

    private func relaySend(to peer: String, blob: Data) async throws {
        _ = try await post("relay/send", body: [
            "from": mailbox, "to": peer, "blob": blob.base64EncodedString(),
        ])
    }

    private func get(_ path: String) async throws -> Data {
        let (data, resp) = try await session.data(from: baseURL.appendingPathComponent(path))
        try check(resp); return data
    }
    private func post(_ path: String, body: [String: Any]) async throws -> Data {
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, resp) = try await session.data(for: req)
        try check(resp); return data
    }
    private func check(_ resp: URLResponse) throws {
        guard let http = resp as? HTTPURLResponse else { throw RelayError.badResponse }
        guard (200..<300).contains(http.statusCode) else { throw RelayError.http(http.statusCode) }
    }
}
