import Foundation

/// Contact & discovery — user-controlled reachability, spoof-proof and spam-proof.
/// Swift parity with `backend/atlas/contact.py` (Python reference of record).
///
/// Findability is OPTIONAL and per-persona (some people want to be found; most don't), a spectrum
/// you choose:
///   PRIVATE   — invite-only; reachable ONLY via a one-time connect CODE you share out-of-band.
///   REACHABLE — verified individuals can ring your published handle; you screen every call.
///   FINDABLE  — your published name appears in lookup; broadly findable (public figures /
///               businesses).
///
/// Every caller is a VERIFIED human (a `personTag`) or an identified business, so caller-ID cannot
/// be spoofed; spam is bounded by Sybil-resistance (one verified human can't become many callers) +
/// per-person rate-limiting + PERSON-SCOPED blocking (block the human, not the handle — gone across
/// all of their personas). Those, plus screening, are what make individual reachability safe.
///
/// Two connection modes:
///   * Mode 1 (mutual code): one side allocates a WINDOW-UNIQUE code and shares it (QR / tap / say
///     it); the other redeems it; on match BOTH are revealed (mutual), then the code is consumed and
///     the window closes. No match -> no reveal to either side.
///   * Mode 2 (caller-ID ring): a verified caller rings a REACHABLE/FINDABLE persona; shows as
///     "unknown" unless the caller opts to reveal; the callee screens (accept / reject / block).
///
/// The hub sees handles + codes (metadata) only; the actual key exchange is the recognition tunnel
/// (out of scope here). A real PAKE over the code is the production hardening for Mode 1.

public enum Reachability: String {
    case privateLevel = "private"
    case reachable = "reachable"
    case findable = "findable"
}

public enum ContactError: Error, Equatable {
    case liveCodeSpaceExhausted
    case noSuchLiveCode
    case calleeInviteOnly
    case callerNotVerified
    case blocked
    case rateLimited
    case noSuchCall
}

/// Mutual reveal on a code match — both sides learn each other's handle, and only then.
public struct Match: Equatable {
    public let owner: String
    public let redeemer: String
    public init(owner: String, redeemer: String) {
        self.owner = owner; self.redeemer = redeemer
    }
}

public struct Call: Equatable {
    public let callId: Int
    public let caller: String        // the caller's handle — shown to the callee ONLY if revealed
    public let callerPerson: Data    // personTag — used for person-scoped block/rate-limit, never displayed
    public let callee: String
    public let revealed: Bool

    public init(callId: Int, caller: String, callerPerson: Data, callee: String, revealed: Bool) {
        self.callId = callId; self.caller = caller; self.callerPerson = callerPerson
        self.callee = callee; self.revealed = revealed
    }

    public func display() -> String {
        revealed ? caller : "unknown (verified human)"
    }
}

public let DEFAULT_CODE_TTL = 300       // seconds the connect code lives (the handshake window)
public let DEFAULT_RATE_LIMIT = 5       // calls per caller-person per window
public let DEFAULT_RATE_WINDOW = 3600

/// Relay-side contact state. Sees handles + codes only; never content.
public final class ContactHub {
    private struct Persona {
        let handle: String
        let level: Reachability
        let name: String?
    }
    private struct PendingCode {
        let owner: String
        let expires: Int
    }

    private let gen: () -> String
    private var personas: [String: Persona] = [:]
    private var names: [String: String] = [:]
    private var codes: [String: PendingCode] = [:]
    private var calls: [Int: Call] = [:]
    private var blocks: [String: Set<Data>] = [:]
    private var rate: [RateKey: Int] = [:]
    private var nextCall = 1

    private struct RateKey: Hashable { let person: Data; let window: Int }

    public init(gen: @escaping () -> String = ContactHub.defaultGen) {
        self.gen = gen
    }

    /// Short + human-typeable; global uniqueness FOR THE WINDOW is enforced by the hub (allocator),
    /// so it only has to be distinct among currently-active codes.
    public static func defaultGen() -> String {
        // base32 of 5 random bytes -> 8 chars (RFC 4648 alphabet, no padding).
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        let bytes = [UInt8](Primitives.randomBytes(5))
        var out = ""
        var buffer = 0, bits = 0
        for b in bytes {
            buffer = (buffer << 8) | Int(b)
            bits += 8
            while bits >= 5 {
                bits -= 5
                out.append(alphabet[(buffer >> bits) & 0x1f])
            }
        }
        return String(out.prefix(8))
    }

    // ---- reachability (opt-in, per persona) ----
    public func setReachability(_ handle: String, _ level: Reachability, name: String? = nil) {
        personas[handle] = Persona(handle: handle, level: level, name: name)
        if level == .findable, let name = name {
            names[name] = handle
        }
    }

    /// Resolve a name to a handle — ONLY personas that opted into FINDABLE appear here.
    public func lookup(_ name: String) -> String? {
        names[name]
    }

    // ---- Mode 1: mutual code ----
    public func allocateCode(_ owner: String, now: Int, ttl: Int = DEFAULT_CODE_TTL) throws -> String {
        expireCodes(now)
        for _ in 0..<1000 {
            let code = gen()
            if codes[code] == nil {                       // unique among ACTIVE codes (window-unique)
                codes[code] = PendingCode(owner: owner, expires: now + ttl)
                return code
            }
        }
        throw ContactError.liveCodeSpaceExhausted
    }

    public func redeemCode(_ code: String, redeemer: String, now: Int) throws -> Match {
        expireCodes(now)
        guard let pc = codes[code] else {
            throw ContactError.noSuchLiveCode                 // wrong/expired -> reveals nothing
        }
        codes[code] = nil                                     // one-time; the window closes
        return Match(owner: pc.owner, redeemer: redeemer)     // mutual reveal, only on match
    }

    private func expireCodes(_ now: Int) {
        for (c, p) in codes where p.expires <= now {
            codes[c] = nil
        }
    }

    // ---- Mode 2: caller-ID ring ----
    public func placeCall(caller: String, callerPerson: Data, callee: String, reveal: Bool,
                          now: Int, rateLimit: Int = DEFAULT_RATE_LIMIT,
                          window: Int = DEFAULT_RATE_WINDOW) throws -> Call {
        if callerPerson.isEmpty {
            throw ContactError.callerNotVerified              // no unverified/spoofed callers
        }
        guard let p = personas[callee], p.level != .privateLevel else {
            throw ContactError.calleeInviteOnly               // invite-only -> reach them with a code
        }
        if blocks[callee]?.contains(callerPerson) == true {
            throw ContactError.blocked                        // person-scoped: across all personas
        }
        let key = RateKey(person: callerPerson, window: now / window)
        let count = (rate[key] ?? 0) + 1
        rate[key] = count
        if count > rateLimit {
            throw ContactError.rateLimited                    // anti-spam
        }
        let call = Call(callId: nextCall, caller: caller, callerPerson: callerPerson,
                        callee: callee, revealed: reveal)
        calls[call.callId] = call
        nextCall += 1
        return call
    }

    /// Callee screens: accept -> proceed to the recognition-tunnel handshake; reject -> dropped.
    /// Set block=true to person-scope-block the caller (stops them across all their personas).
    public func answerCall(_ callId: Int, accept: Bool, block: Bool = false) throws -> Bool {
        guard let call = calls.removeValue(forKey: callId) else {
            throw ContactError.noSuchCall
        }
        if block {
            blocks[call.callee, default: []].insert(call.callerPerson)
        }
        return accept
    }

    public func block(_ callee: String, callerPerson: Data) {
        blocks[callee, default: []].insert(callerPerson)
    }
}
