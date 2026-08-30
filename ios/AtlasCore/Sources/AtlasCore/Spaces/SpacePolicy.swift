import Foundation

/// Space policy — the shared access substrate every vault sits on. Byte-for-byte parity with
/// `backend/atlas/spaces/space_policy.py` (Python is reference-of-record).
///
/// One mechanism — MEMBERSHIP + ROLE under POLICY — expresses sharing, business officer-quorum
/// governance, and agent capability-leashes alike. Every access change is a QUORUM-authorized entry
/// in an APPEND-ONLY, hash-chained log (audit trail + sync source of truth). `head()` is the
/// anchorable digest (signed hash-chain by default; publish it to the beacon for third-party-
/// verifiable immutability — only the head leaves, never content). Revocation is forward-only + logged.
public enum SpaceGovernance {

    static let changeLabel = Data("atlas/space-policy/change/v1".utf8)
    static let entryLabel = Data("atlas/space-policy/entry/v1".utf8)
    static let genesisLabel = Data("atlas/space-policy/genesis/v1".utf8)

    public enum PolicyError: Error, Equatable { case unknownOp, notAuthorized, stale, badChange }

    /// Ordered capability levels — a higher role includes every lower capability.
    public enum Role: Int, Comparable, Sendable {
        case reader = 1, contributor = 2, governor = 3, breakGlass = 4
        public static func < (l: Role, r: Role) -> Bool { l.rawValue < r.rawValue }
    }

    static func lp(_ d: Data) -> Data {
        var n = UInt32(d.count).bigEndian
        return withUnsafeBytes(of: &n) { Data($0) } + d
    }
    static func u16(_ v: Int) -> Data { var n = UInt16(v).bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }
    static func u32(_ v: Int) -> Data { var n = UInt32(v).bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }
    static func u64(_ v: Int) -> Data { var n = UInt64(v).bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }

    public struct Change: Equatable {
        public let op: String                 // "grant" | "revoke" | "set_quorum"
        public let target: Data               // encoded HybridSign.PublicKey (or empty)
        public let role: Role?
        public let quorum: Int?
        public let epoch: Int
        public let afterHead: Data

        public func body() -> Data {
            changeLabel + lp(Data(op.utf8)) + lp(target)
                + u16(role?.rawValue ?? 0) + u32(quorum ?? 0) + u64(epoch) + lp(afterHead)
        }
    }

    public struct LogEntry: Equatable {
        public let seq: Int
        public let prevHash: Data
        public let changeBody: Data
        public let approvers: [Data]          // encoded governor publics who authorized
        public let entryHash: Data

        public static func computeHash(prevHash: Data, changeBody: Data, approvers: [Data]) -> Data {
            // H concatenates its chunks; all fields are length-prefixed, so one buffer == variadic H.
            var buf = entryLabel + lp(prevHash) + lp(changeBody) + u32(approvers.count)
            for a in approvers { buf += lp(a) }
            return Primitives.H(buf)
        }
    }

    /// The living access set + policy for one space, with its append-only authorization log.
    public final class SpacePolicy {
        public let spaceID: Data
        public private(set) var members: [Data: Role]   // encoded public -> Role
        public private(set) var quorum: Int
        public private(set) var log: [LogEntry]

        private init(spaceID: Data, members: [Data: Role], quorum: Int, log: [LogEntry]) {
            self.spaceID = spaceID; self.members = members; self.quorum = quorum; self.log = log
        }

        public static func genesis(spaceID: Data, creator: HybridSign.PublicKey, epoch: Int = 0) -> SpacePolicy {
            let enc = creator.encode()
            let gbody = Primitives.H(genesisLabel + lp(spaceID) + lp(enc) + u64(epoch))
            let entry = LogEntry(seq: 0, prevHash: Data(), changeBody: gbody, approvers: [enc],
                                 entryHash: LogEntry.computeHash(prevHash: Data(), changeBody: gbody, approvers: [enc]))
            return SpacePolicy(spaceID: spaceID, members: [enc: .governor], quorum: 1, log: [entry])
        }

        public func head() -> Data { log.last?.entryHash ?? Data() }
        public func roleOf(_ m: HybridSign.PublicKey) -> Role? { members[m.encode()] }
        public func can(_ m: HybridSign.PublicKey, _ capability: Role) -> Bool {
            guard let r = members[m.encode()] else { return false }
            return r >= capability
        }
        public func governors() -> Set<Data> { Set(members.filter { $0.value >= .governor }.keys) }
        public func membersAt(_ minimum: Role) -> [Data] { members.filter { $0.value >= minimum }.map { $0.key } }

        public func propose(_ op: String, target: HybridSign.PublicKey? = nil, role: Role? = nil,
                            quorum: Int? = nil, epoch: Int) throws -> Change {
            guard ["grant", "revoke", "set_quorum"].contains(op) else { throw PolicyError.unknownOp }
            return Change(op: op, target: target?.encode() ?? Data(), role: role, quorum: quorum,
                          epoch: epoch, afterHead: head())
        }

        @discardableResult
        public func authorize(_ change: Change,
                              approvals: [(HybridSign.PublicKey, Data)]) throws -> LogEntry {
            guard change.afterHead == head() else { throw PolicyError.stale }
            let body = change.body()
            let gov = governors()
            var seen: Set<Data> = []
            for (pub, sig) in approvals {
                let enc = pub.encode()
                if gov.contains(enc), !seen.contains(enc), HybridSign.verify(pub, body, sig) { seen.insert(enc) }
            }
            guard seen.count >= quorum else { throw PolicyError.notAuthorized }

            switch change.op {
            case "grant":
                guard let role = change.role else { throw PolicyError.badChange }
                members[change.target] = role
            case "revoke":
                members[change.target] = nil                 // forward-only; history stays in the log
            case "set_quorum":
                guard let q = change.quorum, q >= 1, q <= governors().count else { throw PolicyError.badChange }
                quorum = q
            default: throw PolicyError.unknownOp
            }

            let approvers = seen.sorted { $0.lexicographicallyPrecedes($1) }
            let entry = LogEntry(seq: log.count, prevHash: head(), changeBody: body, approvers: approvers,
                                 entryHash: LogEntry.computeHash(prevHash: head(), changeBody: body, approvers: approvers))
            log.append(entry)
            return entry
        }

        public func verifyLog() -> Bool {
            var prev = Data()
            for (i, e) in log.enumerated() {
                if e.seq != i || e.prevHash != prev { return false }
                if e.entryHash != LogEntry.computeHash(prevHash: e.prevHash, changeBody: e.changeBody, approvers: e.approvers) { return false }
                prev = e.entryHash
            }
            return true
        }
    }
}
