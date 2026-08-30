import Foundation

/// Tamper-evident, hash-chained record of what happened during a session — the
/// "lab notebook" the app writes as you use it (and as SystemCheck runs). Each
/// entry chains the previous entry's hash, so no past entry can be altered or
/// removed without breaking every hash after it (`verifyChain()` detects it).
///
/// Signing (attribution to THIS device) is layered ON TOP at the app boundary:
/// the app signs `headHash` with the Secure Enclave key, turning "a log" into
/// "a log this device provably produced." The chain here is pure/portable so it
/// builds and tests on the Mac.
///
/// DISCIPLINE (enforced by convention + the API shape): entries carry only a
/// subsystem name, an event name, a pass/fail verdict, and a short human detail
/// string. There is NO field for key material, raw biosignals, or plaintext —
/// the recorder records that something happened and whether it passed, never
/// the secret it happened over.
public final class SessionRecorder {

    public struct Entry: Sendable, Identifiable {
        public let id: Int          // == seq
        public let seq: Int
        public let ts: Double
        public let subsystem: String
        public let event: String
        public let ok: Bool
        public let detail: String
        public let prevHash: Data
        public let hash: Data
    }

    private let genesis: Data
    public private(set) var entries: [Entry] = []

    public init(sessionID: Data) {
        genesis = Primitives.H(Data("atlas/session-recorder/genesis".utf8), sessionID)
    }

    /// Canonical, length-prefixed body — self-contained so the hash is
    /// unambiguous regardless of H()'s internal framing.
    private static func body(seq: Int, ts: Double, subsystem: String, event: String,
                             ok: Bool, detail: String, prev: Data) -> Data {
        var d = Data()
        func lp(_ x: Data) { var n = UInt32(x.count).bigEndian; d.append(Data(bytes: &n, count: 4)); d.append(x) }
        var seqBE = UInt64(seq).bigEndian; d.append(Data(bytes: &seqBE, count: 8))
        var tsBE = ts.bitPattern.bigEndian; d.append(Data(bytes: &tsBE, count: 8))
        lp(Data(subsystem.utf8)); lp(Data(event.utf8))
        d.append(ok ? 1 : 0)
        lp(Data(detail.utf8))
        lp(prev)
        return d
    }

    private static func entryHash(_ body: Data) -> Data {
        Primitives.H(Data("atlas/session-recorder/entry".utf8), body)
    }

    /// Append an event. `ts` is injectable so tests are deterministic; in the app
    /// callers pass `Date().timeIntervalSince1970`.
    @discardableResult
    public func record(subsystem: String, event: String, ok: Bool,
                       detail: String = "", ts: Double) -> Entry {
        let prev = entries.last?.hash ?? genesis
        let seq = entries.count
        let b = Self.body(seq: seq, ts: ts, subsystem: subsystem, event: event, ok: ok, detail: detail, prev: prev)
        let h = Self.entryHash(b)
        let e = Entry(id: seq, seq: seq, ts: ts, subsystem: subsystem, event: event,
                      ok: ok, detail: detail, prevHash: prev, hash: h)
        entries.append(e)
        return e
    }

    /// The head — sign THIS (in the app, under the SE key) to attribute the log.
    public var headHash: Data { entries.last?.hash ?? genesis }

    /// Recompute the whole chain; false if any entry was altered/removed/reordered.
    public func verifyChain() -> Bool {
        var prev = genesis
        for (i, e) in entries.enumerated() {
            guard e.seq == i, e.prevHash == prev else { return false }
            let b = Self.body(seq: e.seq, ts: e.ts, subsystem: e.subsystem, event: e.event,
                              ok: e.ok, detail: e.detail, prev: e.prevHash)
            guard Self.entryHash(b) == e.hash else { return false }
            prev = e.hash
        }
        return true
    }

    public var allPassed: Bool { !entries.isEmpty && entries.allSatisfy(\.ok) }

    /// Portable JSON session proof. The app attaches the SE signature over
    /// `head` (hex) to make it attributable. Contains verdicts only.
    public func exportProof(signatureHex: String? = nil, signerKeyIDHex: String? = nil) -> Data {
        let items: [[String: Any]] = entries.map {
            ["seq": $0.seq, "ts": $0.ts, "subsystem": $0.subsystem, "event": $0.event,
             "ok": $0.ok, "detail": $0.detail, "hash": $0.hash.hexString]
        }
        var obj: [String: Any] = [
            "kind": "atlas/session-proof/v1",
            "genesis": genesis.hexString,
            "head": headHash.hexString,
            "chain_valid": verifyChain(),
            "all_passed": allPassed,
            "entries": items,
        ]
        if let signatureHex { obj["signature"] = signatureHex }
        if let signerKeyIDHex { obj["signer_key_id"] = signerKeyIDHex }
        return (try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys, .prettyPrinted])) ?? Data()
    }
}
