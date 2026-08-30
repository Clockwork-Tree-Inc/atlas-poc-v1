import Foundation

/// Rotating mailboxes + sealed sender — deny the relay the social graph.
/// Swift parity with `backend/atlas/net/privacy/mailbox.py` (Python reference of record).
///
/// The contact layer gives verified, spoof/spam-proof reachability; the transport layer hides
/// message SIZE and TIMING. Both still let the relay see STABLE handles — and a stable "to"
/// address held over time IS the social graph. This removes that last leak.
///
///   ROTATING MAILBOX. Connected parties share a `pairSecret` (from the recognition-tunnel
///   handshake — injected). Each (pair, direction, epoch) hashes under that secret to a fresh
///   opaque id. `epoch` is a public shared clock (a beacon round), so both endpoints derive the
///   SAME id without coordinating, while the relay — lacking the secret — sees unlinkable fresh
///   bytes every epoch and cannot correlate epochs or contacts.
///
///   SEALED SENDER. The relay routes purely on the rotating id; the sender's identity is sealed
///   INSIDE the blob, so the relay learns neither who sent nor (beyond the opaque id) who receives.
///
///   NO DIRECTORY, POLLING-ONLY. There is no enrollment/register step (it would hand the relay a
///   live list of listeners). A box exists to the relay only once a blob is delivered to it, and
///   vanishes on fetch; recipients derive which ids to poll from their own secrets + the epoch.
///
/// Cold first contact uses a PUBLIC INBOX: an opt-in, deliberately STABLE id from a persona's
/// published key, to which anyone may seal a first-contact message. The `SealedEnvelope.blob` is
/// exactly what rides `PrivacyChannel` (padded + batched) on the wire.

public enum MailboxError: Error, Equatable {
    case pairSecretRequired
    case personaPubRequired
    case noSuchContact
}

/// What the relay sees and routes on: a rotating mailbox id and an opaque blob. No sender, no
/// recipient identity, no persona.
public struct SealedEnvelope: Equatable {
    public let mailbox: Data
    public let blob: Data
    public init(mailbox: Data, blob: Data) {
        self.mailbox = mailbox
        self.blob = blob
    }
}

public enum Mailbox {
    public static let mailboxBytes = 16

    // MARK: - Rotating mailbox derivation

    static func lexLess(_ a: Data, _ b: Data) -> Bool {
        let ab = [UInt8](a), bb = [UInt8](b)
        for i in 0..<min(ab.count, bb.count) where ab[i] != bb[i] { return ab[i] < bb[i] }
        return ab.count < bb.count
    }

    /// A stable per-direction tag both endpoints agree on: the sender being the low or high party
    /// (by sorted id) picks the label, so A->B and B->A never collide.
    static func dirLabel(sender: Data, recipient: Data) -> Data {
        let senderIsLo = !lexLess(recipient, sender)   // sender <= recipient => sender is lo
        return Data([senderIsLo ? 0x00 : 0x01])
    }

    /// The rotating mailbox id for `sender`->`recipient` in `epoch`. Both endpoints derive it from
    /// the shared `pairSecret`; the relay, lacking it, sees fresh unlinkable bytes each epoch.
    public static func derive(pairSecret: Data, sender: Data, recipient: Data, epoch: Data) throws -> Data {
        guard !pairSecret.isEmpty else { throw MailboxError.pairSecretRequired }
        let d = Primitives.H(Data("atlas/mailbox/v1".utf8), pairSecret, dirLabel(sender: sender, recipient: recipient), epoch)
        return d.prefix(mailboxBytes)
    }

    /// Per-epoch content key for an established pair — rotates with the mailbox.
    static func msgKey(pairSecret: Data, epoch: Data) -> Data {
        Primitives.hkdf(ikm: pairSecret, info: Data("atlas/mailbox/msgkey/v1".utf8) + epoch)
    }

    // MARK: - Beacon clock + catch-up window (parity with mailbox.py)

    /// The rotation epoch for a drand beacon round — the round INDEX as 8-byte big-endian. The
    /// public shared clock: both endpoints derive the same mailbox for the same round (TOTP-style).
    public static func epochForRound(_ round: UInt64) -> Data { be64(round) }

    /// Recent epochs a recipient polls so downtime / a few-round sender-receiver skew never loses a
    /// message: rounds [now-window, now] inclusive, clamped at 0, NEWEST first.
    public static func catchUpEpochs(nowRound: UInt64, window: UInt64) -> [Data] {
        let start = nowRound >= window ? nowRound - window : 0
        return stride(from: nowRound, through: start, by: -1).map { epochForRound($0) }
    }

    // MARK: - Framing (byte-identical to the Python reference)

    static func be16(_ v: Int) -> Data {
        var b = UInt16(v).bigEndian
        return withUnsafeBytes(of: &b) { Data($0) }
    }
    static func be64(_ v: UInt64) -> Data {
        var b = v.bigEndian
        return withUnsafeBytes(of: &b) { Data($0) }
    }

    static func frame(sender: Data, seq: UInt64, plaintext: Data) -> Data {
        var d = Data()
        d.append(be16(sender.count)); d.append(sender); d.append(be64(seq)); d.append(plaintext)
        return d
    }

    static func unframe(_ buf: Data) -> (sender: Data, seq: UInt64, plaintext: Data)? {
        let b = [UInt8](buf)
        guard b.count >= 2 else { return nil }
        let n = Int(b[0]) << 8 | Int(b[1])
        guard b.count >= 2 + n + 8 else { return nil }
        let sender = Data(b[2..<2 + n])
        var seq: UInt64 = 0
        for i in 0..<8 { seq = (seq << 8) | UInt64(b[2 + n + i]) }
        let pt = Data(b[(10 + n)..<b.count])
        return (sender, seq, pt)
    }

    // MARK: - Sealed-sender envelope

    /// Seal `plaintext` for an established pair. The sender id is sealed INSIDE; the mailbox is
    /// bound as AEAD aad so a blob cannot be replayed under a different address.
    public static func seal(pairSecret: Data, sender: Data, recipient: Data, epoch: Data,
                            seq: UInt64, plaintext: Data) throws -> SealedEnvelope {
        let mailbox = try derive(pairSecret: pairSecret, sender: sender, recipient: recipient, epoch: epoch)
        let blob = try Primitives.aeadEncrypt(key: msgKey(pairSecret: pairSecret, epoch: epoch),
                                              plaintext: frame(sender: sender, seq: seq, plaintext: plaintext),
                                              aad: mailbox)
        return SealedEnvelope(mailbox: mailbox, blob: blob)
    }

    /// Open a blob addressed to one of my rotating mailboxes, or nil if it is not mine / cover /
    /// corrupt (drop silently, like `PrivacyChannel.receive`).
    public static func open(pairSecret: Data, envelope: SealedEnvelope, epoch: Data)
        -> (sender: Data, seq: UInt64, plaintext: Data)? {
        guard let inner = try? Primitives.aeadDecrypt(key: msgKey(pairSecret: pairSecret, epoch: epoch),
                                                      blob: envelope.blob, aad: envelope.mailbox) else { return nil }
        return unframe(inner)
    }

    // MARK: - Public inbox (opt-in cold first contact)

    /// A deliberately STABLE mailbox from a persona's published key — the one findable address for
    /// first contact before any pairSecret exists. Everything after moves to rotating mailboxes.
    public static func publicInboxID(personaPub: Data) throws -> Data {
        guard !personaPub.isEmpty else { throw MailboxError.personaPubRequired }
        return Primitives.H(Data("atlas/mailbox/public/v1".utf8), personaPub).prefix(mailboxBytes)
    }

    /// Seal a cold first-contact message to a persona's PUBLISHED public key. `sealToPub` is the
    /// asymmetric seal (pqcTunnel in production), injected to keep this crypto-core-decoupled.
    public static func sealFirstContact(personaPub: Data, sender: Data, plaintext: Data,
                                        sealToPub: (Data) -> Data) throws -> SealedEnvelope {
        SealedEnvelope(mailbox: try publicInboxID(personaPub: personaPub),
                       blob: sealToPub(frame(sender: sender, seq: 0, plaintext: plaintext)))
    }
}

/// The relay's ENTIRE view: rotating mailbox id -> queued opaque blobs. No handles, no sender, no
/// recipient, no persona — nothing that survives an epoch to become a graph. No register step:
/// a box springs into existence on first delivery and vanishes on fetch.
public final class MailboxRelay {
    private var boxes: [Data: [Data]] = [:]
    public init() {}

    public func deliver(_ envelope: SealedEnvelope) {
        boxes[envelope.mailbox, default: []].append(envelope.blob)
    }

    /// Drain a mailbox. Returns [] for an unknown/empty id (no oracle: absence and empty look the
    /// same). Recipients derive which ids to poll from their own secrets + epoch — never a lookup.
    public func fetch(_ mailbox: Data) -> [Data] {
        defer { boxes[mailbox] = nil }
        return boxes[mailbox] ?? []
    }

    /// Test-only view of stored box ids (never identities).
    var activeBoxCount: Int { boxes.count }
}

/// A persona's client side: holds pairSecrets for its contacts and sends/receives sealed-sender
/// blobs. It derives which mailboxes to poll from its own secrets + the epoch — never enrolls or
/// asks the relay what boxes it has (no directory).
public final class MailboxEndpoint {
    private final class Contact {
        let peerID: Data
        let pairSecret: Data
        var seq: UInt64 = 0
        init(peerID: Data, pairSecret: Data) { self.peerID = peerID; self.pairSecret = pairSecret }
    }

    public let myID: Data
    private let relay: MailboxRelay
    private var contacts: [Data: Contact] = [:]

    public init(myID: Data, relay: MailboxRelay) {
        self.myID = myID
        self.relay = relay
    }

    public func addContact(peerID: Data, pairSecret: Data) {
        contacts[peerID] = Contact(peerID: peerID, pairSecret: pairSecret)
    }

    @discardableResult
    public func send(peerID: Data, plaintext: Data, epoch: Data) throws -> SealedEnvelope {
        guard let c = contacts[peerID] else { throw MailboxError.noSuchContact }
        c.seq += 1
        let env = try Mailbox.seal(pairSecret: c.pairSecret, sender: myID, recipient: peerID,
                                   epoch: epoch, seq: c.seq, plaintext: plaintext)
        relay.deliver(env)
        return env
    }

    /// Pull and open everything from a contact this epoch -> [(seq, plaintext)].
    public func receive(peerID: Data, epoch: Data) throws -> [(seq: UInt64, plaintext: Data)] {
        guard let c = contacts[peerID] else { throw MailboxError.noSuchContact }
        let mailbox = try Mailbox.derive(pairSecret: c.pairSecret, sender: peerID, recipient: myID, epoch: epoch)
        var out: [(UInt64, Data)] = []
        for blob in relay.fetch(mailbox) {
            if let opened = Mailbox.open(pairSecret: c.pairSecret, envelope: SealedEnvelope(mailbox: mailbox, blob: blob), epoch: epoch) {
                out.append((opened.seq, opened.plaintext))
            }
        }
        return out
    }
}
