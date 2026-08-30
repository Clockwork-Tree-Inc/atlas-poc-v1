import Foundation

/// Carries `ServerCustody` placements to/from custodian nodes over the blind `/custody/*` endpoints
/// (`node_server.py`). Transport-agnostic: you supply a per-node async transport (URLSession in the
/// app, an in-memory fake in tests), so the fan-out/rotation logic is verified without a live node.
///
/// The node only ever sees the opaque locator (hex) and the sealed blob (base64) — never the share.
public struct CustodyClient {
    /// `(method, path, jsonBody) -> responseBytes`. Throws on transport/HTTP failure.
    public typealias NodeTransport = (_ method: String, _ path: String, _ body: Data?) async throws -> Data

    /// Resolve a custodian `nodeID` to its transport (its base URL / session). Returns nil if the
    /// node is unknown/unreachable — that node's share is simply skipped (k-of-m tolerates it).
    public let transportFor: (_ nodeID: String) -> NodeTransport?

    public init(transportFor: @escaping (String) -> NodeTransport?) { self.transportFor = transportFor }

    public enum CustodyClientError: Error { case noTransport(String), badResponse }

    // MARK: put / get / drop against one node

    public func store(_ p: ServerCustody.CustodyPlacement) async throws {
        guard let t = transportFor(p.nodeID) else { throw CustodyClientError.noTransport(p.nodeID) }
        let body = try JSONSerialization.data(withJSONObject: [
            "locator": p.locator.hexString, "blob": p.blob.base64EncodedString(),
        ])
        _ = try await t("POST", "/custody/put", body)
    }

    public func fetch(nodeID: String, locator: Data) async throws -> Data {
        guard let t = transportFor(nodeID) else { throw CustodyClientError.noTransport(nodeID) }
        let data = try await t("GET", "/custody/get/\(locator.hexString)", nil)
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let b64 = obj["blob"] as? String, let blob = Data(base64Encoded: b64) else {
            throw CustodyClientError.badResponse
        }
        return blob
    }

    public func drop(nodeID: String, locator: Data) async throws {
        guard let t = transportFor(nodeID) else { throw CustodyClientError.noTransport(nodeID) }
        let body = try JSONSerialization.data(withJSONObject: ["locator": locator.hexString])
        _ = try await t("POST", "/custody/drop", body)
    }

    // MARK: fan-out helpers

    /// Push every placement to its node. Returns the node_ids that accepted the share; a node that
    /// errors is reported but not fatal (as long as >= k succeed, recovery still works).
    @discardableResult
    public func storeAll(_ placements: [ServerCustody.CustodyPlacement]) async -> [String] {
        var ok: [String] = []
        for p in placements {
            if (try? await store(p)) != nil { ok.append(p.nodeID) }
        }
        return ok
    }

    /// Fetch up to `policy.m` shares for the given placements' (nodeID, locator) and reassemble.
    /// Fetches lazily and stops once it has k, so a slow/dead node past the threshold isn't waited on.
    public func collect(from placements: [ServerCustody.CustodyPlacement],
                        policy: ThresholdSeal.ThresholdPolicy, recoveryKey: Data) async throws -> Data {
        var got: [(locator: Data, blob: Data)] = []
        for p in placements {
            if got.count >= policy.m { break }
            if let blob = try? await fetch(nodeID: p.nodeID, locator: p.locator) {
                got.append((p.locator, blob))
            }
        }
        return try ServerCustody.collect(retrieved: got, policy: policy, recoveryKey: recoveryKey)
    }
}
// `Data.hexString` is defined in Beacon.swift and reused here.
