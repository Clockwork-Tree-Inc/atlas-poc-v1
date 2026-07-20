import Foundation
import AtlasCore

/// Talks to the Mac node's mock relying party (a "bank"): register the authenticator,
/// get a challenge, POST the assertion back for verification. SOURCE ONLY — runs on a
/// device against a running node (`python -m atlas.net.node_server`). The real-bank
/// path is the passkey/credential-provider route (see HANDOFF_AUTH.md); this is the
/// phone↔Mac demo.
///
/// Isolation: `@MainActor` — driven directly by the `@MainActor` `AuthModel`, so
/// co-isolating keeps the non-Sendable client and the `Child`/assertion it passes
/// on one actor with nothing crossing a boundary (same pattern as FSRelayClient).
/// The network I/O still suspends off-main inside URLSession's `async` calls.
@MainActor
public final class RPClient {
    public enum RPError: Error { case http(Int), badResponse }

    private let baseURL: URL
    private let session = URLSession(configuration: .ephemeral)
    public init(baseURL: URL) { self.baseURL = baseURL }

    public func register(userId: String, authorship: Child, stepUpPublic: Data?) async throws {
        var body: [String: Any] = [
            "user_id": userId,
            "handle": authorship.handle.base64EncodedString(),
            "public": authPubToJSON(authorship.publicKey),
        ]
        if let su = stepUpPublic { body["step_up_public"] = su.base64EncodedString() }
        _ = try await post("rp/register", body)
    }

    public func challenge(userId: String, action: String, requireStepUp: Bool) async throws -> AuthChallenge {
        let data = try await post("rp/challenge",
                                  ["user_id": userId, "action": action, "require_step_up": requireStepUp])
        guard let o = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let ch = AuthChallenge.fromJSON(o) else { throw RPError.badResponse }
        return ch
    }

    public func verify(userId: String, assertion: VerifiedHumanAssertion) async throws -> Bool {
        let data = try await post("rp/verify", ["user_id": userId, "assertion": assertion.toJSON()])
        guard let o = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let approved = o["approved"] as? Bool else { throw RPError.badResponse }
        return approved
    }

    private func post(_ path: String, _ body: [String: Any]) async throws -> Data {
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw RPError.http((resp as? HTTPURLResponse)?.statusCode ?? -1)
        }
        return data
    }
}
