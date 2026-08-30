import XCTest
@testable import AtlasCore

/// Privacy transport (padding + batching + pluggable backend) — Swift parity with
/// `backend/atlas/net/privacy/` and `backend/tests/test_privacy_transport.py`.
final class PrivacyTransportTests: XCTestCase {
    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
    private func constRng(_ n: Int) -> Data { Data(repeating: 0xff, count: n) }

    // --- padding: shared KAT vector + roundtrip/quantise ---
    func testPaddingKATParity() throws {
        XCTAssertEqual(hex(try Padding.pad(Data("atlas".utf8), to: 16)),
                       "0000000561746c617300000000000000")
        XCTAssertEqual(Padding.bucketFor(1), 256)
        XCTAssertEqual(Padding.bucketFor(256 - 4), 256)
        XCTAssertEqual(Padding.bucketFor(256 - 3), 1024)
        for n in [0, 1, 255, 256, 4096, 100_000] {
            let data = Data(repeating: 0x78, count: n)
            let blob = try Padding.pad(data)
            XCTAssertEqual(try Padding.unpad(blob), data)
            XCTAssertEqual(blob.count, Padding.bucketFor(n))
        }
    }

    func testPadRejectsOverflowAndUnpadRejectsGarbage() {
        XCTAssertThrowsError(try Padding.pad(Data(repeating: 0, count: 4096), to: 4096))
        XCTAssertThrowsError(try Padding.unpad(Data([0])))
        XCTAssertThrowsError(try Padding.unpad(Data([0xff, 0xff, 0xff, 0xff])))
    }

    // --- batching: constant-rate + cover fill ---
    func testBatcherFillsWithCoverAtConstantRate() throws {
        let b = try Batcher(batchSize: 4, blobSize: 260, coverRecipient: { "decoy" }, rng: constRng)
        try b.enqueue(to: "alice", blob: Data(repeating: 1, count: 260))
        let batch = b.flush()
        XCTAssertEqual(batch.count, 4)
        XCTAssertEqual(batch.filter { !$0.cover }.map { $0.to }, ["alice"])
        XCTAssertEqual(batch.filter { $0.cover }.count, 3)
        XCTAssertTrue(batch.allSatisfy { $0.blob.count == 260 })
    }

    func testBatcherEmptyQueueStillEmitsCoverBatch() throws {
        let b = try Batcher(batchSize: 3, blobSize: 260, coverRecipient: { "decoy" }, rng: constRng)
        let batch = b.flush()
        XCTAssertEqual(batch.count, 3)
        XCTAssertTrue(batch.allSatisfy { $0.cover })
    }

    func testBatcherEnqueueRequiresBlobSize() throws {
        let b = try Batcher(batchSize: 2, blobSize: 260, coverRecipient: { "decoy" }, rng: constRng)
        XCTAssertThrowsError(try b.enqueue(to: "x", blob: Data([1, 2, 3])))
    }

    // --- transport end-to-end (toy length-preserving seal, parity with Python) ---
    private let tag = Data("SEAL".utf8)
    private func seal(_ p: Data) -> Data { tag + p }
    private func open(_ c: Data) throws -> Data {
        guard Data(c.prefix(4)) == tag else { throw PrivacyError.malformed }
        return Data(c.dropFirst(4))
    }

    func testChannelEndToEndUniformSizeAndRecovery() throws {
        var wire: [(String, Data)] = []
        let ch = try PrivacyChannel(backend: DirectBackend { to, b in wire.append((to, b)) },
                                    seal: seal, batchSize: 4, coverRecipient: { "decoy" },
                                    cell: 4096, rng: constRng)
        try ch.send(to: "bob", plaintext: Data("hello bob".utf8))
        XCTAssertEqual(ch.pending(), 1)
        try ch.flush()
        XCTAssertEqual(wire.count, 4)
        XCTAssertEqual(Set(wire.map { $0.1.count }).count, 1)            // uniform size
        XCTAssertTrue(wire.allSatisfy { $0.1.count == ch.blobSize })
        let recovered = wire.compactMap { PrivacyChannel.receive($0.1, open: open) }
        XCTAssertEqual(recovered, [Data("hello bob".utf8)])             // exactly one real
    }

    func testChannelRejectsOversizeAndReceiveDropsCover() throws {
        let ch = try PrivacyChannel(backend: DirectBackend { _, _ in }, seal: seal,
                                    batchSize: 3, coverRecipient: { "decoy" }, cell: 256, rng: constRng)
        XCTAssertThrowsError(try ch.send(to: "bob", plaintext: Data(repeating: 0x78, count: 256)))
        XCTAssertNil(PrivacyChannel.receive(Data(repeating: 0xff, count: 260), open: open))
    }

    // --- backend options: direct works, tor/mixnet are stubs ---
    func testBackendFactoryAndStubs() throws {
        XCTAssertTrue(try makeBackend(.direct, send: { _, _ in }) is DirectBackend)
        XCTAssertTrue(try makeBackend(.tor) is TorBackend)
        XCTAssertTrue(try makeBackend(.mixnet) is MixnetBackend)
        XCTAssertThrowsError(try makeBackend(.direct))                  // needs a send sink
        XCTAssertThrowsError(try TorBackend().deliver([]))
        XCTAssertThrowsError(try MixnetBackend().deliver([]))
    }
}
