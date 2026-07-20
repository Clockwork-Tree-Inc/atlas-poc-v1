import Foundation

/// Alarm-triggered forensic window (C8). Mirrors `backend/atlas/session/forensic.py`.
///
/// On any alarm, seal the multimodal capture and stream it OFF-DEVICE to the
/// user's non-custodial storage:
///  * ESCAPE-FIRST — `open` seals + emits the header (wrapped key) AND the first
///    burst immediately, before any sustain loop.
///  * NO LOCAL BUFFER — only the symmetric content key is held; each chunk is
///    sealed and handed to the sink, plaintext never retained.
///  * SEALED TO THE USER — the content key is KEM-wrapped to the user's RECOVERY
///    public key; the storage host holds only opaque ciphertext.
///  * TIMESTAMP-ANCHORED — every chunk binds a beacon round.
///  * TAMPER-EVIDENT — chunks are hash-chained; drop/reorder/alter breaks it.
///
/// STATUS: unrun until built on a Mac (`swift test`). The multimodal capture
/// bytes come from the app (camera/mic); this core seals + chains + emits them.
public enum AlarmCause: String, Sendable {
    case panicCode = "panic_code"
    case panicPhrase = "panic_phrase"
    case improperDisconnect = "improper_disconnect"
    case suspiciousLifecycle = "suspicious_lifecycle"
    case failedRecovery = "failed_recovery"
}

public struct ForensicHeader: Sendable {
    public let cause: String
    public let wrappedKey: [String: Data]      // KEM-wrap to the recovery key
    public let genesis: Data
}

public struct ForensicChunk: Sendable {
    public let seq: Int
    public let cause: String
    public let beaconDrandRound: Data
    public let beaconRandomness: Data
    public let prevHash: Data
    public let ciphertext: Data
    public let chunkHash: Data

    public static func computeHash(seq: Int, cause: String, drandRound: Data, randomness: Data,
                                   prevHash: Data, ciphertext: Data) -> Data {
        var s = UInt32(seq).bigEndian
        let seqBytes = withUnsafeBytes(of: &s) { Data($0) }
        return Primitives.H(Data("atlas/forensic/link".utf8), seqBytes, Data(cause.utf8),
                            drandRound, randomness, prevHash, ciphertext)
    }
}

public enum ForensicError: Error { case tampering(String), closed }

public final class ForensicWindow {
    public static let genesis = Data(repeating: 0, count: 32)
    private static let chunkAAD = Data("atlas/forensic/chunk".utf8)

    private let cause: AlarmCause
    private let contentKey: Data                 // RAM-only; NO plaintext buffer
    private let sink: (String, Any) -> Void
    private var head = ForensicWindow.genesis
    private var seq = 0
    private var open = true

    private init(cause: AlarmCause, contentKey: Data, sink: @escaping (String, Any) -> Void) {
        self.cause = cause; self.contentKey = contentKey; self.sink = sink
    }

    /// Fire the window: seal + emit header AND the first burst immediately.
    public static func open(cause: AlarmCause, recoveryPub: HybridKEM.PublicKey,
                            initialCapture: Data, beacon: BeaconRound,
                            sink: @escaping (String, Any) -> Void) throws -> ForensicWindow {
        let contentKey = Primitives.randomBytes(32)
        let wrapped = try Vault.wrapKey(to: recoveryPub, key: contentKey)
        sink("header", ForensicHeader(cause: cause.rawValue, wrappedKey: wrapped, genesis: genesis))
        let w = ForensicWindow(cause: cause, contentKey: contentKey, sink: sink)
        try w.capture(initialCapture, beacon: beacon)   // initial burst, immediately
        return w
    }

    @discardableResult
    public func capture(_ plaintext: Data, beacon: BeaconRound) throws -> ForensicChunk {
        guard open else { throw ForensicError.closed }
        seq += 1
        let drandRound = beacon.drandRound()
        let rnd = beacon.randomness
        let ct = try Primitives.aeadEncrypt(key: contentKey, plaintext: plaintext, aad: ForensicWindow.chunkAAD)
        let hash = ForensicChunk.computeHash(seq: seq, cause: cause.rawValue, drandRound: drandRound,
                                             randomness: rnd, prevHash: head, ciphertext: ct)
        let chunk = ForensicChunk(seq: seq, cause: cause.rawValue, beaconDrandRound: drandRound,
                                  beaconRandomness: rnd, prevHash: head, ciphertext: ct, chunkHash: hash)
        head = hash
        sink("chunk", chunk)                     // emitted; plaintext goes out of scope
        return chunk
    }

    public func close() { open = false }
}

/// USER side: unwrap the content key with the recovery keypair, verify the chain,
/// and return the decrypted captures in order.
public func openForensicWindow(header: ForensicHeader, chunks: [ForensicChunk],
                               recoveryKP: HybridKEM.Keypair) throws -> [Data] {
    let contentKey = try Vault.unwrapKey(recoveryKP, bundle: header.wrappedKey)
    var prev = header.genesis
    var out: [Data] = []
    let aad = Data("atlas/forensic/chunk".utf8)
    for (i, c) in chunks.enumerated() {
        if c.seq != i + 1 || c.prevHash != prev { throw ForensicError.tampering("chain break at seq \(c.seq)") }
        let expect = ForensicChunk.computeHash(seq: c.seq, cause: c.cause, drandRound: c.beaconDrandRound,
                                               randomness: c.beaconRandomness, prevHash: c.prevHash,
                                               ciphertext: c.ciphertext)
        if expect != c.chunkHash { throw ForensicError.tampering("altered chunk at seq \(c.seq)") }
        out.append(try Primitives.aeadDecrypt(key: contentKey, blob: c.ciphertext, aad: aad))
        prev = c.chunkHash
    }
    return out
}
