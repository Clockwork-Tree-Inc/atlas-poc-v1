// AtlasDebugEmitter.swift — DEBUG-BUILD-ONLY telemetry tap.
//
// Reference emitter to wire into the iOS app. It streams the on-device gate's
// existing state to the Mac harness as newline-delimited JSON over a plain TCP
// socket. It is an OBSERVER: it reads what the gate already computed and reports
// it. It must never feed samples into the gate, and it must never ship.
//
// Two hard rules, both enforced here:
//   1. The whole type is wrapped in `#if DEBUG` so it cannot exist in a release build.
//   2. It exposes only an `emit(...)` sink. There is no path back into the session,
//      the enclave, or the signal source — it cannot inject.
//
// Wire it in where the gate already updates (e.g. after each PoLE evaluation and on
// each removal-state transition) by calling `AtlasDebugEmitter.shared?.emit(...)`.
// In a release build `AtlasDebugEmitter.shared` is nil and every call compiles out.

#if DEBUG
import Foundation
import Network

final class AtlasDebugEmitter {
    static var shared: AtlasDebugEmitter?

    private let conn: NWConnection
    private let queue = DispatchQueue(label: "atlas.debug.emitter")
    private let start = Date()

    /// Call once, early, in a DEBUG build only, e.g.
    ///   AtlasDebugEmitter.start(host: "192.168.1.50", port: 7731)  // the Mac's LAN IP
    static func start(host: String, port: UInt16) {
        let ep = NWEndpoint.Host(host)
        let pt = NWEndpoint.Port(rawValue: port)!
        let c = NWConnection(host: ep, port: pt, using: .tcp)
        let e = AtlasDebugEmitter(conn: c)
        c.start(queue: e.queue)
        shared = e
    }

    private init(conn: NWConnection) { self.conn = conn }

    private func monotonicSeconds() -> Double { Date().timeIntervalSince(start) }

    /// Emit one telemetry tick. All fields optional except the two always-present ones.
    /// Pass only what a given call site knows; the harness reads what it needs.
    func emit(kind: String = "gate",
              pLive: Double? = nil,
              operate: Bool? = nil,
              epoch: Int? = nil,
              ppgBpm: Double? = nil,
              bcgBpm: Double? = nil,
              spo2: Double? = nil,
              skinTempC: Double? = nil,
              sameBodyR: Double? = nil,
              removalState: String? = nil,
              keyWiped: Bool? = nil,
              attestTier: String? = nil,
              note: String? = nil) {
        var obj: [String: Any] = ["t": monotonicSeconds(), "kind": kind]
        if let v = pLive { obj["p_live"] = v }
        if let v = operate { obj["operate"] = v }
        if let v = epoch { obj["epoch"] = v }
        if let v = ppgBpm { obj["ppg_bpm"] = v }
        if let v = bcgBpm { obj["bcg_bpm"] = v }
        if let v = spo2 { obj["spo2"] = v }
        if let v = skinTempC { obj["skin_temp_c"] = v }
        if let v = sameBodyR { obj["same_body_r"] = v }
        if let v = removalState { obj["removal_state"] = v }
        if let v = keyWiped { obj["key_wiped"] = v }
        if let v = attestTier { obj["attest_tier"] = v }
        if let v = note { obj["note"] = v }

        guard let data = try? JSONSerialization.data(withJSONObject: obj),
              var line = String(data: data, encoding: .utf8) else { return }
        line += "\n"
        conn.send(content: line.data(using: .utf8), completion: .idempotent)
    }
}
#endif
