import XCTest
@testable import AtlasCore

final class ProvenanceTests: XCTestCase {
    private let realDepth = [0.42, 0.61, 0.95, 1.30, 0.55, 0.78, 1.10, 0.33]
    private let screenDepth = [0.300, 0.301, 0.299, 0.300, 0.302, 0.300, 0.301, 0.299]

    private func liveAttestation(_ att: AttestationSubsystem, _ rnd: BeaconRound) -> LivenessAttestation {
        let g = LivenessGate()
        for (_, l) in Synthetic.liveStream(40) { g.update(pSGivenLive: l.0, pSGivenNotLive: l.1) }
        return att.attest(g.state(sensorDigest: Data("s".utf8), drandRound: rnd.drandRound()))!
    }
    private func meta() -> CaptureMetadata {
        CaptureMetadata(cameraIntrinsics: "f=26mm", motion: "still",
                        capturedAt: "2026-06-27T12:00:00Z", depthSummary: "varied")
    }

    func testPADAcceptsRealRejectsScreen() {
        XCTAssertTrue(PAD.check(depthMap: realDepth, moireScore: 0.1).passed)
        XCTAssertFalse(PAD.check(depthMap: screenDepth, moireScore: 0.1).passed)
        XCTAssertFalse(PAD.check(depthMap: realDepth, moireScore: 0.9).passed) // moiré
    }

    func testCapstoneSignVerifyRoundTrip() throws {
        let tree = try IdentityTree.build(tskSeed: Primitives.randomBytes(32), sphincs: StubSphincs())
        let att = AttestationSubsystem()
        let rnd = LocalBeacon(periodS: 3).round(at: 1)
        let ledger = LedgerStub()
        let photo = Data("earliest-frame".utf8) + Primitives.randomBytes(64)
        let bundle = try Provenance.signCapture(content: photo, depthMap: realDepth, moireScore: 0.1,
                                                metadata: meta(), authorship: tree.child(.authorship),
                                                attestation: liveAttestation(att, rnd), beaconRound: rnd, ledger: ledger)
        XCTAssertTrue(Provenance.verify(bundle, content: photo, ledger: ledger).ok)
        // tamper -> integrity fails
        XCTAssertFalse(Provenance.verify(bundle, content: Data("tampered".utf8), ledger: ledger).integrityOK)
    }

    func testScreenReplayRejectedAtCapture() throws {
        let tree = try IdentityTree.build(tskSeed: Primitives.randomBytes(32), sphincs: StubSphincs())
        let att = AttestationSubsystem()
        let rnd = LocalBeacon(periodS: 3).round(at: 1)
        XCTAssertThrowsError(try Provenance.signCapture(content: Data("x".utf8), depthMap: screenDepth,
            moireScore: 0.1, metadata: meta(), authorship: tree.child(.authorship),
            attestation: liveAttestation(att, rnd), beaconRound: rnd, ledger: LedgerStub(),
            padPolicy: .reject)) { err in
            guard case ProvenanceError.padRejected = err else { return XCTFail("expected padRejected") }
        }
        // default (advisory): a flagged capture STILL signs — accountability is
        // the guarantee, PAD is advisory.
        let advisory = try Provenance.signCapture(content: Data("x".utf8), depthMap: screenDepth,
            moireScore: 0.1, metadata: meta(), authorship: tree.child(.authorship),
            attestation: liveAttestation(att, rnd), beaconRound: rnd, ledger: LedgerStub())
        XCTAssertFalse(advisory.pad.passed)
    }
}
