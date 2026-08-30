import XCTest
@testable import AtlasCore

/// Exercises CustodyClient's fan-out over a FAKE multi-node transport (dictionaries standing in for
/// the live nodes' /custody stores), so the store→collect→rotate wire path is verified without a
/// live node. Mirrors the node_server /custody/{put,get,drop} contract.
final class CustodyClientTests: XCTestCase {
    /// One fake node = an in-memory {locatorHex: blob} store, driven through the same JSON contract.
    final class FakeNode {
        var store: [String: Data] = [:]
        func transport(_ method: String, _ path: String, _ body: Data?) async throws -> Data {
            if method == "POST", path == "/custody/put" {
                let o = try JSONSerialization.jsonObject(with: body!) as! [String: Any]
                store[o["locator"] as! String] = Data(base64Encoded: o["blob"] as! String)!
                return Data("{\"ok\":true}".utf8)
            }
            if method == "GET", path.hasPrefix("/custody/get/") {
                let loc = String(path.dropFirst("/custody/get/".count))
                guard let blob = store[loc] else { throw NSError(domain: "404", code: 404) }
                return try JSONSerialization.data(withJSONObject: ["blob": blob.base64EncodedString()])
            }
            if method == "POST", path == "/custody/drop" {
                let o = try JSONSerialization.jsonObject(with: body!) as! [String: Any]
                store[o["locator"] as! String] = nil
                return Data("{\"ok\":true}".utf8)
            }
            throw NSError(domain: "route", code: 400)
        }
    }

    private let policy = try! ThresholdSeal.ThresholdPolicy(n: 3, m: 2)
    private let sel = Data("selector".utf8)

    private func fabric(_ ids: [String]) -> (CustodyClient, [String: FakeNode]) {
        let map = Dictionary(uniqueKeysWithValues: ids.map { ($0, FakeNode()) })
        let client = CustodyClient { id in map[id].map { node in node.transport } }
        return (client, map)
    }

    func testStoreThenCollectOverTheNetwork() async throws {
        let (client, nodes) = fabric(["a", "b", "c"])
        let serverHalf = Primitives.randomBytes(32), rkey = Primitives.randomBytes(32)
        let pls = try ServerCustody.distribute(
            serverHalf: serverHalf, nodes: [.init(nodeID: "a"), .init(nodeID: "b"), .init(nodeID: "c")],
            policy: policy, recoverySelector: sel, recoveryKey: rkey)

        let accepted = await client.storeAll(pls)
        XCTAssertEqual(Set(accepted), ["a", "b", "c"])
        XCTAssertEqual(nodes["a"]!.store.count, 1)         // node holds exactly its one opaque blob

        let got = try await client.collect(from: pls, policy: policy, recoveryKey: rkey)
        XCTAssertEqual(got, serverHalf)
    }

    func testCollectStillWorksWithOneNodeDown() async throws {
        // client that only knows a and c (node b "unreachable") — k=2 tolerates it
        let (client, _) = fabric(["a", "c"])
        let serverHalf = Primitives.randomBytes(32), rkey = Primitives.randomBytes(32)
        let pls = try ServerCustody.distribute(
            serverHalf: serverHalf, nodes: [.init(nodeID: "a"), .init(nodeID: "b"), .init(nodeID: "c")],
            policy: policy, recoverySelector: sel, recoveryKey: rkey)
        _ = await client.storeAll(pls)                     // b silently skipped
        let got = try await client.collect(from: pls, policy: policy, recoveryKey: rkey)
        XCTAssertEqual(got, serverHalf)
    }
}
