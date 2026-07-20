import XCTest
@testable import AtlasCore

/// Media capture -> sealed vault ingestion. Mirrors `backend/tests/test_media_vault.py`.
/// Every captured item is provenance-signed AND sealed under live presence in one
/// step, re-verified accountable on open, fails closed on no-presence / wrong
/// biometric / swapped provenance. Audio has no camera PAD but is accountable.
final class MediaVaultTests: XCTestCase {
    private let bio = Data(repeating: 0xA5, count: 64)
    private let realDepth = [0.42, 0.61, 0.95, 1.30, 0.55, 0.78, 1.10, 0.33]

    private func livePole(_ epoch: Data) -> PoLEState {
        let g = LivenessGate()
        for (_, l) in Synthetic.liveStream(40) { g.update(pSGivenLive: l.0, pSGivenNotLive: l.1) }
        return g.state(sensorDigest: Data("s".utf8), drandRound: epoch)
    }
    private func deadPole(_ epoch: Data) -> PoLEState {
        PoLEState(pLive: 0.0, stateDigest: Data("d".utf8), drandRound: epoch, operate: false)
    }
    private func liveAtt(_ att: AttestationSubsystem, _ epoch: Data) -> LivenessAttestation {
        let g = LivenessGate()
        for (_, l) in Synthetic.liveStream(40) { g.update(pSGivenLive: l.0, pSGivenNotLive: l.1) }
        return att.attest(g.state(sensorDigest: Data("s".utf8), drandRound: epoch))!
    }

    private func makeStore() throws -> (store: MediaVaultStore, att: AttestationSubsystem) {
        let tree = try IdentityTree.build(tskSeed: Primitives.randomBytes(32), sphincs: StubSphincs())
        let author = tree.child(.authorship)
        let vault = SecureVaultStore(enclave: ModelEnclave(), biometric: bio, author: author)
        return (MediaVaultStore(vault: vault, authorship: author), AttestationSubsystem())
    }

    func testPhotoCaptureSealsAndReopensAccountable() throws {
        let (store, att) = try makeStore()
        let b = LocalBeacon(periodS: 3).round(at: 1); let epoch = b.drandRound()
        let photo = Data("PNG".utf8) + Primitives.randomBytes(64)
        _ = try store.capture(kind: .photo, name: "selfie", content: photo, liveBiometric: bio,
                              pole: livePole(epoch), beacon: b, attestation: liveAtt(att, epoch),
                              depthMap: realDepth, moireScore: 0.1)
        let (content, verdict) = try store.open("selfie", liveBiometric: bio, pole: livePole(epoch))
        XCTAssertEqual(content, photo)
        XCTAssertTrue(verdict.accountable)
    }

    func testAudioCaptureHasNoCameraPADButAccountable() throws {
        let (store, att) = try makeStore()
        let b = LocalBeacon(periodS: 3).round(at: 1); let epoch = b.drandRound()
        let voice = Data("RIFF".utf8) + Primitives.randomBytes(200)
        let rec = try store.capture(kind: .audio, name: "memo", content: voice, liveBiometric: bio,
                                    pole: livePole(epoch), beacon: b, attestation: liveAtt(att, epoch))  // no depthMap
        let (content, verdict) = try store.open("memo", liveBiometric: bio, pole: livePole(epoch))
        XCTAssertEqual(content, voice)
        XCTAssertTrue(verdict.accountable)                    // accountable despite no camera PAD
        XCTAssertFalse(verdict.padAdvisory.passed)            // PAD honestly N/A for audio
        XCTAssertEqual(rec.bundle.metadata.motion, "audio")
    }

    func testMediaAtRestIsUnreadableBrick() throws {
        let (store, att) = try makeStore()
        let b = LocalBeacon(periodS: 3).round(at: 1); let epoch = b.drandRound()
        let secret = Data("TOP-SECRET-FOOTAGE-PLAINTEXT".utf8)
        _ = try store.capture(kind: .photo, name: "x", content: secret, liveBiometric: bio,
                              pole: livePole(epoch), beacon: b, attestation: liveAtt(att, epoch),
                              depthMap: realDepth, moireScore: 0.1)
        let brick = store.rawAtRest("x")!
        XCTAssertFalse(brick.range(of: secret) != nil)
        XCTAssertGreaterThan(brick.count, 16)
    }

    func testOpenWithoutPresenceFailsClosed() throws {
        let (store, att) = try makeStore()
        let b = LocalBeacon(periodS: 3).round(at: 1); let epoch = b.drandRound()
        _ = try store.capture(kind: .photo, name: "x", content: Data("data".utf8), liveBiometric: bio,
                              pole: livePole(epoch), beacon: b, attestation: liveAtt(att, epoch),
                              depthMap: realDepth, moireScore: 0.1)
        XCTAssertThrowsError(try store.open("x", liveBiometric: bio, pole: deadPole(epoch)))
    }

    func testWrongBiometricCannotOpen() throws {
        let (store, att) = try makeStore()
        let b = LocalBeacon(periodS: 3).round(at: 1); let epoch = b.drandRound()
        _ = try store.capture(kind: .audio, name: "memo", content: Data("voice".utf8), liveBiometric: bio,
                              pole: livePole(epoch), beacon: b, attestation: liveAtt(att, epoch))
        XCTAssertThrowsError(try store.open("memo", liveBiometric: Data(repeating: 0, count: 64), pole: livePole(epoch)))
    }

    func testSwappedProvenanceBundleRefused() throws {
        let (store, att) = try makeStore()
        let b = LocalBeacon(periodS: 3).round(at: 1); let epoch = b.drandRound()
        _ = try store.capture(kind: .photo, name: "a", content: Data("AAA-content".utf8), liveBiometric: bio,
                              pole: livePole(epoch), beacon: b, attestation: liveAtt(att, epoch),
                              depthMap: realDepth, moireScore: 0.1)
        let recB = try store.capture(kind: .photo, name: "bb", content: Data("BBB-content".utf8), liveBiometric: bio,
                                     pole: livePole(epoch), beacon: b, attestation: liveAtt(att, epoch),
                                     depthMap: realDepth, moireScore: 0.1)
        store._testGraftBundle(onto: "a", from: recB)          // graft bb's provenance onto a
        XCTAssertThrowsError(try store.open("a", liveBiometric: bio, pole: livePole(epoch))) { err in
            guard case MediaVaultError.provenanceRefused = err else { return XCTFail("expected provenanceRefused") }
        }
    }
}
