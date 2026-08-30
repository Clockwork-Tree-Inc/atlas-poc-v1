import Foundation

/// Sealed records — medical + other sensitive records. Byte-for-byte parity with
/// `backend/atlas/records/records.py` (Python is reference-of-record). Assembly only — composes
/// AES-GCM sealing, Shamir threshold, a tamper-evident hash-chained access log, and beacon-round gates.
///
/// FOUR grants, each with its own lifetime:
///   1. PATIENT → OWN FILE — permanent.
///   2. PATIENT → TREATING CLINICIAN — this episode only (live + present + in-window; ends at discharge).
///   3. CLINICIAN → OWN ENCOUNTER NOTE — separate object, retained until retentionEnd then unreadable.
///   4. REOPEN THE RETAINED RECORD for a dispute — threshold(doctor share AND governing-body share),
///      per record (a stolen body-share opens nothing alone; blast radius is one record).
/// RETENTION ≠ READABILITY: the law requires KEEPING, not keeping READABLE — the retained record
/// opens only on a trigger and becomes unreadable past retention (expiry as arithmetic). Every open,
/// including the patient's own, is logged; a reopen / break-glass NOTIFIES the patient.
public enum Records {

    public enum RecordsError: Error, Equatable {
        case accessDenied       // discharged, outside window, not present, or past retention
        case thresholdNotMet    // a reopen lacked BOTH the doctor and governing-body share
    }

    static let accessLabel = Data("atlas/records/access".utf8)
    static let chainLabel = Data("atlas/records/chain".utf8)
    static let zero = Data(repeating: 0, count: 32)

    static func u64(_ v: Int) -> Data { var n = UInt64(v).bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }

    // MARK: append-only access log

    public struct AccessEntry: Equatable {
        public let seq: Int
        public let who: String
        public let action: String
        public let round: Int
        public let prev: Data
        public let notify: Bool
    }

    /// Tamper-evident record of every access — symmetric (even the patient's own opens are logged).
    public final class AccessLog {
        public private(set) var entries: [AccessEntry] = []
        public private(set) var head = zero

        public init() {}

        static func commit(_ who: String, _ action: String, _ round: Int, _ notify: Bool) -> Data {
            // `notify` IS bound into the commitment — the "patient was told" bit must not be silently
            // flippable by an adversary holding the log.
            Primitives.H(accessLabel, Data(who.utf8), Data(action.utf8), u64(round), Data([notify ? 1 : 0]))
        }

        @discardableResult
        public func record(who: String, action: String, round: Int, notify: Bool = false) -> AccessEntry {
            let e = AccessEntry(seq: entries.count, who: who, action: action, round: round, prev: head, notify: notify)
            head = Primitives.H(chainLabel, head, Self.commit(who, action, round, notify))
            entries.append(e)
            return e
        }

        public func verify() -> Bool {
            var h = Records.zero
            for e in entries {
                if e.prev != h { return false }
                h = Primitives.H(chainLabel, h, Self.commit(e.who, e.action, e.round, e.notify))
            }
            return h == head
        }

        /// Accesses the patient should be pushed in real time (review-unseal / break-glass).
        public func notifications() -> [AccessEntry] { entries.filter { $0.notify } }
    }

    // MARK: sealed record + grants

    public struct SealedRecord: Equatable {
        public let blob: Data
        public init(blob: Data) { self.blob = blob }
    }

    public static func sealRecord(_ content: Data, contentKey: Data, aad: Data = Data()) throws -> SealedRecord {
        SealedRecord(blob: try Primitives.aeadEncrypt(key: contentKey, plaintext: content, aad: aad))
    }

    static func open(_ record: SealedRecord, contentKey: Data, aad: Data = Data()) throws -> Data {
        try Primitives.aeadDecrypt(key: contentKey, blob: record.blob, aad: aad)
    }

    /// 1 — PATIENT → OWN FILE (permanent). Always opens; still logged (symmetric trail).
    public static func patientOpenOwn(_ record: SealedRecord, contentKey: Data, log: AccessLog,
                                      nowRound: Int, patient: String = "patient", aad: Data = Data()) throws -> Data {
        log.record(who: patient, action: "open-own", round: nowRound)
        return try open(record, contentKey: contentKey, aad: aad)
    }

    /// 2 — PATIENT → TREATING CLINICIAN (this episode only; ends at discharge).
    public final class EpisodeGrant {
        public let wrappedKey: Data      // aead(episodeKey, contentKey)
        public let opensFrom: Int
        public let opensUntil: Int
        public var discharged: Bool
        public init(wrappedKey: Data, opensFrom: Int, opensUntil: Int, discharged: Bool = false) {
            self.wrappedKey = wrappedKey; self.opensFrom = opensFrom; self.opensUntil = opensUntil
            self.discharged = discharged
        }
    }

    /// Opens ONLY for a live, present clinician, within the episode window, before discharge.
    public static func clinicianOpenEpisode(_ grant: EpisodeGrant, record: SealedRecord, episodeKey: Data,
                                            nowRound: Int, presenceLive: Bool, log: AccessLog,
                                            clinician: String = "clinician", aad: Data = Data()) throws -> Data {
        var reason: String? = nil
        if grant.discharged { reason = "discharged" }
        else if !(grant.opensFrom <= nowRound && nowRound <= grant.opensUntil) { reason = "outside-window" }
        else if !presenceLive { reason = "not-present" }
        if let reason {   // a denied attempt is logged too (attempts + outcomes both recorded)
            log.record(who: clinician, action: "open-episode-denied:\(reason)", round: nowRound)
            throw RecordsError.accessDenied
        }
        let contentKey = try Primitives.aeadDecrypt(key: episodeKey, blob: grant.wrappedKey)
        log.record(who: clinician, action: "open-episode", round: nowRound)
        return try open(record, contentKey: contentKey, aad: aad)
    }

    public static func discharge(_ grant: EpisodeGrant) { grant.discharged = true }

    /// 3 — CLINICIAN → OWN ENCOUNTER NOTE (retained until retentionEnd, then unreadable).
    public static func clinicianOpenNote(_ note: SealedRecord, noteKey: Data, nowRound: Int,
                                         retentionEnd: Int, log: AccessLog, clinician: String = "clinician",
                                         aad: Data = Data()) throws -> Data {
        if nowRound > retentionEnd { throw RecordsError.accessDenied }
        log.record(who: clinician, action: "open-note", round: nowRound)
        return try open(note, contentKey: noteKey, aad: aad)
    }

    /// 4 — REOPEN THE RETAINED RECORD (threshold: doctor share AND governing-body share), per record.
    public static func splitReopenShares(_ contentKey: Data) -> (doctor: Shamir.Share, body: Shamir.Share) {
        let s = Shamir.split(contentKey, n: 2, k: 2)
        return (s[0], s[1])
    }

    public static func reopenRetained(_ record: SealedRecord, doctorShare: Shamir.Share, bodyShare: Shamir.Share,
                                      nowRound: Int, retentionEnd: Int, log: AccessLog,
                                      patient: String = "patient", aad: Data = Data()) throws -> Data {
        if nowRound > retentionEnd { throw RecordsError.accessDenied }
        let contentKey = Shamir.combine([doctorShare, bodyShare])
        let plain: Data
        do {
            plain = try open(record, contentKey: contentKey, aad: aad)
        } catch {
            // Log the FAILED ATTEMPT — a failed reopen must not be recorded as a successful one.
            log.record(who: "dispute", action: "reopen-retained-failed", round: nowRound, notify: true)
            throw RecordsError.thresholdNotMet    // one share, or a foreign record's share → wrong key
        }
        log.record(who: "dispute", action: "reopen-retained", round: nowRound, notify: true)
        return plain
    }

    /// BREAK-GLASS — the unconscious patient. Any clinician may open; the open is LOUD (logged + notified).
    public static func breakGlassOpen(_ record: SealedRecord, breakGlassKey: Data, wrappedContentKey: Data,
                                      nowRound: Int, log: AccessLog, clinician: String = "on-call") throws -> Data {
        let contentKey = try Primitives.aeadDecrypt(key: breakGlassKey, blob: wrappedContentKey)
        log.record(who: clinician, action: "break-glass", round: nowRound, notify: true)
        return try open(record, contentKey: contentKey)
    }
}
