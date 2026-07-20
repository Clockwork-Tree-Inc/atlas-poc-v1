import XCTest
@testable import AtlasCore

/// Change-based ambient signal: XOR vs previous snapshot + entropy across
/// snapshots. Mirrors `backend/tests/test_signal_source.py` (change/entropy half),
/// with byte-exact parity vectors from the Python reference.
final class ChangeDetectionTests: XCTestCase {

    /// A source whose sampler yields the given windows in order (then repeats last).
    private func seqSource(_ windows: [Data]) -> ChangeDetectingSignalSource {
        var i = 0
        return ChangeDetectingSignalSource(kind: "ambient", simulated: true, channels: [], liveFloor: 2) {
            let w = windows[min(i, windows.count - 1)]; i += 1; return w
        }
    }

    // -- parity vectors (values computed by the Python reference) --------------

    func testHelperParityVectors() {
        XCTAssertEqual(AmbientChange.popcount(Data([0xff, 0x0f])), 12)
        XCTAssertEqual(AmbientChange.spreadDelta(Data([1, 2, 3, 4, 5, 6, 7, 8])), 162)
        XCTAssertEqual(AmbientChange.spreadDelta(Data([0x10])), 80)
        let ab = Array(repeating: [Data("A".utf8), Data("B".utf8)], count: 8).flatMap { $0 }
        let (sh, mn) = AmbientChange.distributionEntropies(ab)
        XCTAssertEqual(sh, 1.0, accuracy: 1e-9)      // two states, half each -> 1 bit
        XCTAssertEqual(mn, 1.0, accuracy: 1e-9)
    }

    func testMinEntropyBelowShannonForDominantState() {
        let (sh, mn) = AmbientChange.distributionEntropies(
            Array(repeating: Data("A".utf8), count: 13) + [Data("B".utf8), Data("C".utf8), Data("D".utf8)])
        XCTAssertLessThan(mn, sh)                    // worst-case < average
    }

    // -- XOR change detection --------------------------------------------------

    func testFrozenSnapshotFailsClosed() throws {
        let frozen = Data([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
        let src = seqSource([frozen, frozen])
        XCTAssertTrue(try src.sample().present)      // bootstrap
        let second = try src.sample()
        XCTAssertEqual(second.changedBits, 0)
        XCTAssertFalse(second.present)               // frozen/replay -> gate closed
    }

    func testConstantBaselineCancelsOnlyChangeCounts() throws {
        let a = Data([0xf0, 0x0f, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        let b = Data([0xf0, 0x1f, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        let src = seqSource([a, b])
        _ = try src.sample()
        let s = try src.sample()
        XCTAssertEqual(s.changedBits, (0x0f ^ 0x1f).nonzeroBitCount)   // steady 0xf0 cancels
        XCTAssertTrue(s.present)
    }

    func testChangeDrivesTimingNotLevel() throws {
        let base = Data(repeating: 0x80, count: 8)
        let small = Data([0x80, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80])
        let big = Data([0x80, 0xff, 0x7f, 0x01, 0x80, 0x80, 0x80, 0x80])
        let s1 = seqSource([base, small]); _ = try s1.sample(); let t1 = try s1.sample().timing
        let s2 = seqSource([base, big]); _ = try s2.sample(); let t2 = try s2.sample().timing
        XCTAssertNotEqual(t1, t2)                    // jitter tracks change, not level
    }

    // -- entropy across snapshots ---------------------------------------------

    func testTwoFrameLoopFlaggedByMinEntropy() throws {
        let a = Data((1...8).map(UInt8.init)), b = Data((9...16).map(UInt8.init))
        var windows: [Data] = []
        for _ in 0..<16 { windows.append(a); windows.append(b) }
        let loop = seqSource(windows)
        var last: LiveSignalSample!
        for _ in 0..<24 { last = try loop.sample() }
        XCTAssertFalse(last.present)                 // 2 symbols -> min-entropy ~1 < floor
        XCTAssertNotNil(last.changedBits); XCTAssertGreaterThan(last.changedBits!, 0)  // XOR was fooled
        XCTAssertLessThan(last.minEntropyBits!, 2.5)

        // genuine noise (all-distinct snapshots) stays present throughout.
        let noisy = ChangeDetectingSignalSource(kind: "ambient", simulated: true, liveFloor: 2) {
            Primitives.randomBytes(8)
        }
        for _ in 0..<24 { XCTAssertTrue(try noisy.sample().present) }
    }

    // -- ambient change DRIVES liveness (PoLE), not synthetic data ------------

    func testAmbientLivenessLikelihoodsMapping() {
        // bootstrap (no change info) -> neutral
        let boot = LiveSignalSample(timing: Data([0]), present: true, kind: "ambient", simulated: true)
        XCTAssertEqual(ambientLivenessLikelihoods(boot).live, 0.5)
        // gated out (frozen/looped) -> strong not-live
        let frozen = LiveSignalSample(timing: Data([0]), present: false, kind: "ambient", simulated: true,
                                      changedBits: 0)
        let f = ambientLivenessLikelihoods(frozen)
        XCTAssertLessThan(f.live, 0.1); XCTAssertGreaterThan(f.notLive, 0.9)
        // healthy change -> live evidence dominates
        let live = LiveSignalSample(timing: Data([0]), present: true, kind: "ambient", simulated: true,
                                    changedBits: 30, minEntropyBits: 4.0)
        let l = ambientLivenessLikelihoods(live)
        XCTAssertGreaterThan(l.live, l.notLive)
    }

    func testLiveAmbientStreamYieldsOperatingPole() throws {
        let src = ChangeDetectingSignalSource(kind: "ambient", simulated: true, liveFloor: 2) {
            Primitives.randomBytes(8)
        }
        let pole = try poleFromAmbient(src, ticks: 40, drandRound: Data(count: 8))
        XCTAssertTrue(pole.operate)               // live change -> PoLE operates
    }

    func testFrozenAmbientStreamFailsLivenessClosed() throws {
        let frozen = Data([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
        let src = ChangeDetectingSignalSource(kind: "ambient", simulated: true, liveFloor: 2) { frozen }
        let pole = try poleFromAmbient(src, ticks: 40, drandRound: Data(count: 8))
        XCTAssertFalse(pole.operate)              // frozen -> liveness fails closed
    }

    func testBothEntropiesReportedAndOrdered() throws {
        let src = ChangeDetectingSignalSource(kind: "ambient", simulated: true, liveFloor: 2) {
            Primitives.randomBytes(8)
        }
        var samples: [LiveSignalSample] = []
        for _ in 0..<(AmbientChange.entropyWarm + 6) { samples.append(try src.sample()) }
        XCTAssertNil(samples[0].entropyBits); XCTAssertNil(samples[0].minEntropyBits)   // bootstrap
        let last = samples.last!
        XCTAssertNotNil(last.entropyBits); XCTAssertNotNil(last.minEntropyBits)
        XCTAssertLessThanOrEqual(last.minEntropyBits!, last.entropyBits! + 1e-9)        // min <= Shannon
        XCTAssertGreaterThan(last.entropyBits!, 2.0)
    }
}
