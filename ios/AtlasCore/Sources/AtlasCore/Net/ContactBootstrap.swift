import Foundation

/// First-contact bootstrap — be FINDABLE without pinning down a mailbox. Swift parity with
/// `backend/atlas/net/privacy/contact.py` (Python reference of record).
///
/// A rotating beacon-clocked CONNECT CODE (TOTP-style) plus a rotating RENDEZVOUS (a knock-spot, never a
/// mailbox: derived from the persona's public key for an OPEN persona, or from the connect code for a
/// CODE_ONLY one). A stranger seals a knock to the persona's KEM key and drops it at the rendezvous; the
/// persona sees the caller id, accepts or rejects, and only on accept does the shared secret promote to
/// the per-pair secret that seeds the rotating pair mailbox. This is the code/rendezvous/gate core.
public enum ContactBootstrap {

    public static let codeDigits = 8

    public enum ContactMode: String, Sendable {
        case open = "open"
        case codeOnly = "code-only"
        case contactsOnly = "contacts-only"
        case closed = "closed"
    }

    // --- rotating connect code ---

    public static func connectCode(_ codeSecret: Data, epoch: Data) -> String {
        let d = Primitives.H(Data("atlas/connect-code/v1".utf8), codeSecret, epoch)
        let n = d.prefix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        return String(format: "%0\(codeDigits)llu", n % 100_000_000)
    }

    public static func currentCode(_ codeSecret: Data, nowRound: UInt64) -> String {
        connectCode(codeSecret, epoch: Mailbox.epochForRound(nowRound))
    }

    public static func codeValid(_ codeSecret: Data, code: String, nowRound: UInt64, window: UInt64 = 2) -> Bool {
        Mailbox.catchUpEpochs(nowRound: nowRound, window: window)
            .contains { ctEq(connectCode(codeSecret, epoch: $0), code) }
    }

    private static func ctEq(_ a: String, _ b: String) -> Bool {
        let x = Array(a.utf8), y = Array(b.utf8)
        guard x.count == y.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<x.count { diff |= x[i] ^ y[i] }
        return diff == 0
    }

    // --- rotating rendezvous (a knock-spot, never a mailbox) ---

    public static func openRendezvous(_ personaPubEnc: Data, epoch: Data) -> Data {
        Data(Primitives.H(Data("atlas/rendezvous-open/v1".utf8), personaPubEnc, epoch).prefix(Mailbox.mailboxBytes))
    }

    public static func codeRendezvous(_ code: String, epoch: Data) -> Data {
        Data(Primitives.H(Data("atlas/rendezvous-code/v1".utf8), Data(code.utf8), epoch).prefix(Mailbox.mailboxBytes))
    }

    // --- accept gate + promotion ---

    public struct KnockDecision {
        public let allowed: Bool
        public let caller: Data?      // caller's persona public key (caller-ID) when a knock is opened
        public let reason: String
    }

    public static func gateKnock(_ mode: ContactMode, callerPubEnc: Data, presentedCode: String?,
                                 codeSecret: Data, nowRound: UInt64, knownContacts: Set<Data>,
                                 window: UInt64 = 2) -> KnockDecision {
        switch mode {
        case .open:
            return KnockDecision(allowed: true, caller: callerPubEnc, reason: "open")
        case .codeOnly:
            let ok = presentedCode.map { codeValid(codeSecret, code: $0, nowRound: nowRound, window: window) } ?? false
            return KnockDecision(allowed: ok, caller: ok ? callerPubEnc : nil, reason: ok ? "code-ok" : "code-invalid")
        case .contactsOnly:
            let ok = knownContacts.contains(callerPubEnc)
            return KnockDecision(allowed: ok, caller: ok ? callerPubEnc : nil, reason: ok ? "known" : "not-a-contact")
        case .closed:
            return KnockDecision(allowed: false, caller: nil, reason: "closed")
        }
    }

    /// On accept, the KEM shared secret becomes the per-pair secret that seeds the rotating pair mailbox.
    public static func promotePairSecret(_ shared: Data) -> Data {
        Primitives.hkdf(ikm: shared, info: Data("atlas/contact/pair-secret/v1".utf8))
    }
}
