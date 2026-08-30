import Foundation

/// Client-side consumer of Atlas's public EPOCH beacon (the epoch key).
///
/// The phone NEVER runs the aggregator — that is TRUSTED Atlas-server infrastructure
/// (`backend/atlas/beacon/epoch_service.py::EpochBeaconService`), the only component that holds the
/// signing key and observes Living-Key arrivals. The phone only CONSUMES signed epoch rounds and
/// VERIFIES them against the PINNED aggregator public key before use — it trusts nothing it cannot
/// verify. This mirrors the blind relay's consume-and-verify discipline in
/// `backend/atlas/net/node_server.py` (`beacon_now`).
public enum EpochBeaconClient {

    public enum ClientError: Error, Equatable {
        case malformed              // the served JSON is not a well-formed epoch round
        case unpinnedAggregator     // the node advertised an aggregator key that is not the pinned one
        case badSignature           // the round's signature does not verify under the pinned key
        case http                   // non-2xx response fetching /beacon
    }

    /// Parse the JSON the node serves at `/beacon` into an `EpochRound` (NO verification yet).
    public static func parse(_ json: [String: Any]) -> EpochRound? {
        guard let epoch = json["epoch"] as? Int,
              let randHex = json["randomness"] as? String,
              let sigHex = json["signature"] as? String else { return nil }
        let anchorHex = (json["anchor"] as? String) ?? ""
        return EpochRound(epoch: epoch, randomness: Data(hex: randHex),
                          anchor: Data(hex: anchorHex), signature: Data(hex: sigHex))
    }

    /// Verify a served epoch round against the PINNED aggregator key. Throws unless the served
    /// aggregator key (if advertised) EQUALS the pin AND the signature verifies. Returns the trusted
    /// round. Fail-closed: a substituted key or an invalid/absent signature is rejected, never used.
    public static func verified(_ json: [String: Any],
                                pinnedAggregator pub: HybridSign.PublicKey) throws -> EpochRound {
        guard let rnd = parse(json) else { throw ClientError.malformed }
        if let servedHex = json["aggregator_pub"] as? String,
           let served = HybridSign.PublicKey(encoded: Data(hex: servedHex)), served != pub {
            throw ClientError.unpinnedAggregator     // never trust a substituted aggregator key
        }
        guard verifyEpochRound(rnd, pub) else { throw ClientError.badSignature }
        return rnd
    }

    /// Fetch `/beacon` from a node and return the round ONLY if it verifies against the pinned key.
    public static func fetchVerified(from nodeBase: URL, pinnedAggregator pub: HybridSign.PublicKey,
                                     session: URLSession = .shared) async throws -> EpochRound {
        let url = nodeBase.appendingPathComponent("beacon")
        let (data, resp) = try await session.data(from: url)
        if let http = resp as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw ClientError.http
        }
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ClientError.malformed
        }
        return try verified(json, pinnedAggregator: pub)
    }
}
