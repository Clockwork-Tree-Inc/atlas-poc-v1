import Foundation

/// Privacy transport — metadata protection for the relay path. Swift parity with
/// `backend/atlas/net/privacy/` (Python reference of record).
///
/// The relay stores-and-forwards OPAQUE, per-persona pseudonymous blobs but still sees
/// envelope metadata: from/to mailbox, blob SIZE, and ORDER/TIMING. This module removes
/// the size/timing/volume signals:
///   * `Padding`        — quantise a message to a fixed SIZE bucket (applied to plaintext,
///                        before sealing) so size reveals only the bucket.
///   * `Batcher`        — release blobs in fixed-count batches padded with indistinguishable
///                        COVER blobs, decorrelating timing and volume.
///   * `PrivacyChannel` — compose the two over a pluggable `Backend` (direct now; Tor
///                        `.onion` / a PQC mixnet later, behind the same interface).

public enum PrivacyError: Error, Equatable {
    case tooLarge
    case exceedsCell(Int)
    case malformed
    case wrongBlobSize(Int)
    case notImplemented
    case badBackend
}

/// Length-hiding padding. MUST be applied to PLAINTEXT before sealing.
public enum Padding {
    public static let buckets: [Int] = [256, 1024, 4096, 16384, 65536, 262144, 1048576]
    static let header = 4

    /// Smallest total blob size that holds `n` payload bytes (incl. the 4-byte header);
    /// beyond the ladder, a whole multiple of the largest bucket.
    public static func bucketFor(_ n: Int) -> Int {
        precondition(n >= 0)
        let need = n + header
        for b in buckets where need <= b { return b }
        let top = buckets.last!
        return ((need + top - 1) / top) * top
    }

    /// Frame as `uint32(len) || data || zero-fill`, sized to a bucket (or exactly `to`).
    public static func pad(_ data: Data, to: Int? = nil) throws -> Data {
        if data.count >= (1 << 32) { throw PrivacyError.tooLarge }
        let n = UInt32(data.count)
        var body = Data([UInt8((n >> 24) & 0xff), UInt8((n >> 16) & 0xff),
                         UInt8((n >> 8) & 0xff), UInt8(n & 0xff)])
        body.append(data)
        let size: Int
        if let to = to {
            if to < body.count { throw PrivacyError.exceedsCell(to) }
            size = to
        } else {
            size = bucketFor(data.count)
        }
        body.append(Data(count: size - body.count))  // zero fill
        return body
    }

    public static func unpad(_ blob: Data) throws -> Data {
        let b = Data(blob)  // normalise slice indices to 0-based
        guard b.count >= header else { throw PrivacyError.malformed }
        let n = (Int(b[0]) << 24) | (Int(b[1]) << 16) | (Int(b[2]) << 8) | Int(b[3])
        guard header + n <= b.count else { throw PrivacyError.malformed }
        return b.subdata(in: header ..< (header + n))
    }
}

/// One blob queued for delivery. `cover` is sender/test bookkeeping — never serialised.
public struct OutboundItem: Equatable {
    public let to: String
    public let blob: Data
    public let cover: Bool
    public init(to: String, blob: Data, cover: Bool = false) {
        self.to = to; self.blob = blob; self.cover = cover
    }
}

/// Fixed-count batcher with constant-rate cover fill.
public final class Batcher {
    public let batchSize: Int
    public let blobSize: Int
    private let coverRecipient: () -> String
    private let rng: (Int) -> Data
    private var queue: [OutboundItem] = []

    public init(batchSize: Int, blobSize: Int, coverRecipient: @escaping () -> String,
                rng: @escaping (Int) -> Data = { Primitives.randomBytes($0) }) throws {
        guard batchSize >= 1 else { throw PrivacyError.malformed }
        guard blobSize >= 1 else { throw PrivacyError.malformed }
        self.batchSize = batchSize; self.blobSize = blobSize
        self.coverRecipient = coverRecipient; self.rng = rng
    }

    /// Queue a real blob. It MUST already be padded to the channel's blob size.
    public func enqueue(to: String, blob: Data) throws {
        guard blob.count == blobSize else { throw PrivacyError.wrongBlobSize(blob.count) }
        queue.append(OutboundItem(to: to, blob: blob))
    }

    public func pending() -> Int { queue.count }

    private func coverItem() -> OutboundItem {
        OutboundItem(to: coverRecipient(), blob: rng(blobSize), cover: true)
    }

    /// Release exactly `batchSize` items — real first, then cover to fill (constant rate).
    public func flush() -> [OutboundItem] {
        var batch = Array(queue.prefix(batchSize))
        queue.removeFirst(min(batchSize, queue.count))
        while batch.count < batchSize { batch.append(coverItem()) }
        return batch
    }
}

/// Pluggable delivery backend.
public protocol Backend { func deliver(_ batch: [OutboundItem]) throws }

/// No network anonymity — but padding + batching still hide size/timing/volume.
public struct DirectBackend: Backend {
    private let send: (String, Data) -> Void
    public init(send: @escaping (String, Data) -> Void) { self.send = send }
    public func deliver(_ batch: [OutboundItem]) throws { for i in batch { send(i.to, i.blob) } }
}

/// STUB — SOCKS5 Tor + `.onion` relay (also solves node reachability). Not wired yet.
public struct TorBackend: Backend {
    public init() {}
    public func deliver(_ batch: [OutboundItem]) throws { throw PrivacyError.notImplemented }
}

/// STUB — Atlas's own PQC mixnet (Loopix + Sphinx over ML-KEM, operator-run). Not built yet.
public struct MixnetBackend: Backend {
    public init() {}
    public func deliver(_ batch: [OutboundItem]) throws { throw PrivacyError.notImplemented }
}

public enum BackendKind: String { case direct, tor, mixnet }

public func makeBackend(_ kind: BackendKind,
                        send: ((String, Data) -> Void)? = nil) throws -> Backend {
    switch kind {
    case .direct:
        guard let send = send else { throw PrivacyError.badBackend }
        return DirectBackend(send: send)
    case .tor: return TorBackend()
    case .mixnet: return MixnetBackend()
    }
}

/// Compose padding + batching + a backend into one send path over a fixed `cell` size.
public final class PrivacyChannel {
    private let backend: Backend
    private let seal: (Data) throws -> Data
    private let cell: Int
    public let blobSize: Int
    private let batcher: Batcher

    public init(backend: Backend, seal: @escaping (Data) throws -> Data, batchSize: Int,
                coverRecipient: @escaping () -> String, cell: Int = 4096,
                rng: @escaping (Int) -> Data = { Primitives.randomBytes($0) }) throws {
        self.backend = backend; self.seal = seal; self.cell = cell
        self.blobSize = try seal(Padding.pad(Data(), to: cell)).count
        self.batcher = try Batcher(batchSize: batchSize, blobSize: blobSize,
                                   coverRecipient: coverRecipient, rng: rng)
    }

    public func pending() -> Int { batcher.pending() }

    public func send(to: String, plaintext: Data) throws {
        let blob = try seal(Padding.pad(plaintext, to: cell))
        guard blob.count == blobSize else { throw PrivacyError.wrongBlobSize(blob.count) }
        try batcher.enqueue(to: to, blob: blob)
    }

    public func flush() throws { try backend.deliver(batcher.flush()) }

    /// Recover a message, or `nil` if it is cover/garbage (open or unpad fails silently).
    public static func receive(_ blob: Data, open: (Data) throws -> Data) -> Data? {
        guard let opened = try? open(blob) else { return nil }
        return try? Padding.unpad(opened)
    }
}
