import Foundation

/// Beacons (§3). Mirrors `backend/atlas/beacon/`.
public struct BeaconRound: Sendable, Equatable {
    public let round: Int
    public let randomness: Data
    public let signature: Data
    public init(round: Int, randomness: Data, signature: Data = Data()) {
        self.round = round; self.randomness = randomness; self.signature = signature
    }
    /// 8-byte big-endian epoch id.
    public func drandRound() -> Data {
        var r = UInt64(round).bigEndian
        return withUnsafeBytes(of: &r) { Data($0) }
    }
}

public protocol Beacon {
    var periodS: TimeInterval { get }
    func round(at t: TimeInterval) -> BeaconRound
}

/// Public beacon — the epoch key (§3.2). drand on the Mac; deterministic
/// stand-in for offline/preview. Both conform to `Beacon`.
public struct LocalBeacon: Beacon {
    public let genesisTime: TimeInterval
    public let periodS: TimeInterval
    public let chainSeed: Data
    public init(genesisTime: TimeInterval = 0, periodS: TimeInterval = 3,
                chainSeed: Data = Data("atlas-local-drand".utf8)) {
        self.genesisTime = genesisTime; self.periodS = periodS; self.chainSeed = chainSeed
    }
    public func roundNumber(at t: TimeInterval) -> Int {
        t < genesisTime ? 0 : 1 + Int((t - genesisTime) / periodS)
    }
    public func round(at t: TimeInterval) -> BeaconRound {
        let n = roundNumber(at: t)
        var nb = UInt64(n).bigEndian
        let rnd = Primitives.sha256(chainSeed, withUnsafeBytes(of: &nb) { Data($0) })
        return BeaconRound(round: n, randomness: rnd)
    }
}

/// Real drand client (§1.3, §3.2). Used on the Mac/phone with network; the
/// transport is injectable so it is testable offline.
public struct DrandHTTPBeacon: Beacon {
    public let relay: String
    public let chainHash: String
    public var periodS: TimeInterval
    public var genesisTime: TimeInterval
    /// Default: League of Entropy "quicknet".
    public static let quicknetChainHash =
        "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

    public init(relay: String = "https://api.drand.sh",
                chainHash: String = DrandHTTPBeacon.quicknetChainHash,
                periodS: TimeInterval = 3, genesisTime: TimeInterval = 0) {
        self.relay = relay; self.chainHash = chainHash
        self.periodS = periodS; self.genesisTime = genesisTime
    }

    public func roundNumber(at t: TimeInterval) -> Int {
        t < genesisTime ? 0 : 1 + Int((t - genesisTime) / periodS)
    }

    /// Synchronous `round(at:)` is provided for protocol conformance/preview but
    /// real fetches should use `fetchLatest()`/`fetch(round:)` async below.
    public func round(at t: TimeInterval) -> BeaconRound {
        BeaconRound(round: roundNumber(at: t), randomness: Data())  // see async API
    }

    public func fetchLatest(session: URLSession = .shared) async throws -> BeaconRound {
        try await fetch(path: "latest", session: session)
    }
    public func fetch(round: Int, session: URLSession = .shared) async throws -> BeaconRound {
        try await fetch(path: String(round), session: session)
    }
    private func fetch(path: String, session: URLSession) async throws -> BeaconRound {
        let url = URL(string: "\(relay)/\(chainHash)/public/\(path)")!
        let (data, _) = try await session.data(from: url)
        let obj = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        return BeaconRound(round: obj["round"] as! Int,
                           randomness: Data(hex: obj["randomness"] as! String),
                           signature: Data(hex: (obj["signature"] as? String) ?? ""))
    }
}

extension Data {
    init(hex: String) {
        var d = Data(); var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            if let b = UInt8(hex[i..<j], radix: 16) { d.append(b) }
            i = j
        }
        self = d
    }
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
