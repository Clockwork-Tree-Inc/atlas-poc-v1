import Foundation
import CryptoKit
import AtlasCore

/// PQC session tunnel — phone -> Mac backend (the PoC's server node).
///
/// Uses the REAL hybrid KEM (`AtlasCore.HybridKEM`, ML-KEM-768 + X25519) to derive
/// a shared tunnel key, then AES-256-GCM (`AtlasCore.Tunnel`) for payloads. This is
/// the genuine post-quantum handshake; only the TRANSPORT (HTTP to the Mac) is the
/// integration seam — point `baseURL` at the Mac backend running on your LAN.
///
/// STATUS: unrun until built on a Mac to a device against a running backend.
public final class AtlasTunnelClient {

    public enum TunnelError: Error { case noServerKey, http(Int), badResponse }

    private let baseURL: URL
    private var tunnelKey: Data?
    private var sessionID: String?
    private let session = URLSession(configuration: .ephemeral)

    public init(baseURL: URL) { self.baseURL = baseURL }

    /// Handshake: fetch the Mac's hybrid KEM public key, encapsulate to it, POST the
    /// ciphertext, and derive the shared tunnel key. After this, `send` is encrypted
    /// under a post-quantum-derived key.
    public func handshake() async throws {
        let serverPK = try await getServerPublicKey()
        let enc = try HybridKEM.encapsulate(to: serverPK)
        // Tell the server our ciphertext so it can derive the SAME shared secret.
        let data = try await post("kem/complete", body: [
            "mlkemCT": enc.mlkemCT.base64EncodedString(),
            "x25519EphPK": enc.x25519EphPK.base64EncodedString(),
        ])
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: String],
              let session = obj["session"] else { throw TunnelError.badResponse }
        self.tunnelKey = enc.shared
        self.sessionID = session
    }

    /// Seal a message under the PQC-derived tunnel key and POST it. `mode` = .normal
    /// or .verifiedHuman (Mode-2 gate). The whole nonce||ct||tag blob is `Message
    /// .ciphertext` (there is no separate nonce field).
    public func send(_ plaintext: Data, mode: SendMode = .normal) async throws -> Data {
        guard let key = tunnelKey, let session = sessionID else { throw TunnelError.noServerKey }
        let msg = try Tunnel.seal(plaintext, mode: mode, key: key)
        return try await post("tunnel/message", body: [
            "session": session,
            "ciphertext": msg.ciphertext.base64EncodedString(),
            "mode": String(mode.rawValue),
        ])
    }

    // MARK: - transport (the Mac-endpoint seam)

    private func getServerPublicKey() async throws -> HybridKEM.PublicKey {
        let data = try await get("kem/public-key")
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: String],
              let ekB64 = obj["mlkemEK"], let xpkB64 = obj["x25519PK"],
              let ek = Data(base64Encoded: ekB64), let xpk = Data(base64Encoded: xpkB64) else {
            throw TunnelError.badResponse
        }
        return HybridKEM.PublicKey(mlkemEK: ek, x25519PK: xpk)
    }

    private func get(_ path: String) async throws -> Data {
        let (data, resp) = try await session.data(from: baseURL.appendingPathComponent(path))
        try check(resp)
        return data
    }
    private func post(_ path: String, body: [String: String]) async throws -> Data {
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, resp) = try await session.data(for: req)
        try check(resp)
        return data
    }
    private func check(_ resp: URLResponse) throws {
        guard let http = resp as? HTTPURLResponse else { throw TunnelError.badResponse }
        guard (200..<300).contains(http.statusCode) else { throw TunnelError.http(http.statusCode) }
    }
}
