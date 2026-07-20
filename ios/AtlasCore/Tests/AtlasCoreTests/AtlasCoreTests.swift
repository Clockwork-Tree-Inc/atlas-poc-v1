import XCTest
@testable import AtlasCore

/// A deterministic test double for the SPHINCS+ root (see HybridSign.swift seam).
/// Real builds inject CryptoKit SLH-DSA or a vendored implementation; the tree
/// structure and recovery logic do not depend on the signature internals.
struct StubSphincs: SphincsProvider {
    func keypair(fromSeed seed: Data) -> (publicKey: Data, secretKey: Data) {
        let pk = Primitives.H(Data("stub/spx/pk".utf8), seed)
        let sk = Primitives.H(Data("stub/spx/sk".utf8), seed)
        return (pk, sk)
    }
    func sign(secretKey: Data, message: Data) -> Data { Primitives.H(secretKey, message) }
    func verify(publicKey: Data, message: Data, signature: Data) -> Bool { true }
}

final class AtlasCoreTests: XCTestCase {
    func testAEADRoundTrip() throws {
        let k = Primitives.randomBytes(32)
        let blob = try Primitives.aeadEncrypt(key: k, plaintext: Data("hi".utf8), aad: Data("aad".utf8))
        XCTAssertEqual(try Primitives.aeadDecrypt(key: k, blob: blob, aad: Data("aad".utf8)), Data("hi".utf8))
    }

    func testShamir2of3() {
        let secret = Primitives.randomBytes(32)
        let shares = Shamir.split(secret, n: 3, k: 2)
        XCTAssertEqual(Shamir.combine([shares[0], shares[1]]), secret)
        XCTAssertEqual(Shamir.combine([shares[0], shares[2]]), secret)
        XCTAssertEqual(Shamir.combine([shares[1], shares[2]]), secret)
    }

    func testRatchetForwardSecrecy() {
        let k0 = Primitives.randomBytes(32)
        let entropy = Primitives.randomBytes(32)
        let k1 = Derivation.ratchet(k0, entropyT: entropy, beaconT: Data("b".utf8), drandRound: Data(count: 8))
        // Attacker with k0 but not the secret entropy cannot reach k1.
        let guess = Derivation.ratchet(k0, entropyT: Data(count: 32), beaconT: Data("b".utf8), drandRound: Data(count: 8))
        XCTAssertNotEqual(guess, k1)
        XCTAssertEqual(Derivation.ratchet(k0, entropyT: entropy, beaconT: Data("b".utf8), drandRound: Data(count: 8)), k1)
    }

    func testIdentityTreeDistinctHandles() throws {
        let tree = try IdentityTree.build(tskSeed: Primitives.randomBytes(32), sphincs: StubSphincs())
        let handles = Set(IdentityContext.allCases.map { tree.child($0).handle })
        XCTAssertEqual(handles.count, 4)
    }

    private func noisy(_ template: Data, frac: Double) -> Data {
        var out = template
        var rng = SystemRandomNumberGenerator()
        let nbits = Int(Double(template.count * 8) * frac)
        for _ in 0..<nbits {
            let i = Int.random(in: 0..<template.count, using: &rng)
            out[out.startIndex + i] ^= (1 << Int.random(in: 0..<8, using: &rng))
        }
        return out
    }

    func testStratifiedRecovery() throws {
        let sphincs = StubSphincs()
        let seed = Primitives.randomBytes(32)
        let tree = try IdentityTree.build(tskSeed: seed, sphincs: sphincs)
        let bio = Primitives.randomBytes(256)
        let device = ModelEnclave()
        let enr = try Recovery.enrol(tree, biometricTemplate: bio, device: device, passcode: "hunter2", sphincs: sphincs)

        // device-present card + in-person via Enclave (robust)
        XCTAssertEqual(try Recovery.recoverViaCard(enr, device: device, cardShare: enr.shareCard,
            liveBiometric: bio, attested: true, userAuthorized: true, sphincs: sphincs).tskSeed, seed)
        XCTAssertEqual(try Recovery.recoverInPerson(enr, device: device, liveBiometric: bio,
            attested: true, inPersonTrustedContext: true, userAuthorized: true, sphincs: sphincs).tskSeed, seed)

        // Enclave's robust matcher accepts a 25%-noisy casual read (device-present)
        let casual = noisy(bio, frac: 0.25)
        XCTAssertEqual(try Recovery.recoverViaCard(enr, device: device, cardShare: enr.shareCard,
            liveBiometric: casual, attested: true, userAuthorized: true, sphincs: sphincs).tskSeed, seed)

        // total-loss: NO Enclave, NO biometric — the two portable shares (card + context)
        XCTAssertEqual(try Recovery.recoverTotalLoss(enr, cardShare: enr.shareCard, contextShare: enr.shareContext,
            attested: true, inPersonTrustedContext: true, userAuthorized: true, sphincs: sphincs).tskSeed, seed)

        // lost device: a DIFFERENT device's Enclave can't release (device-bound),
        // but total-loss still works without any Enclave.
        let newDevice = ModelEnclave(); newDevice.enrolBiometric(bio)
        XCTAssertThrowsError(try Recovery.recoverViaCard(enr, device: newDevice, cardShare: enr.shareCard,
            liveBiometric: bio, attested: true, userAuthorized: true, sphincs: sphincs))

        // never store the biometric: the Enclave-sealed copy is the only biometric artifact,
        // and it does not contain the raw template. No fuzzy helper exists anymore.
        XCTAssertFalse(enr.enclaveSealedBio.range(of: bio) != nil)
    }

    func testLivenessGateLiveVsSpoof() {
        let gl = LivenessGate(); for (_, l) in Synthetic.liveStream(40) { gl.update(pSGivenLive: l.0, pSGivenNotLive: l.1) }
        XCTAssertTrue(gl.state(sensorDigest: Data("d".utf8), drandRound: Data(count: 8)).operate)
        let gs = LivenessGate(); for (_, l) in Synthetic.spoofStream(40) { gs.update(pSGivenLive: l.0, pSGivenNotLive: l.1) }
        XCTAssertFalse(gs.state(sensorDigest: Data("d".utf8), drandRound: Data(count: 8)).operate)
    }

    func testRecognitionSharedTunnelAndTwoModes() throws {
        let sphincs = StubSphincs()
        let seed = Primitives.randomBytes(32); let boot = Primitives.randomBytes(32)
        let A = Device(name: "A", identity: try IdentityTree.build(tskSeed: seed, sphincs: sphincs), bootstrapTunnelKey: boot)
        let B = Device(name: "B", identity: try IdentityTree.build(tskSeed: seed, sphincs: sphincs), bootstrapTunnelKey: boot)
        let lk = Data(repeating: 1, count: 32), epochKey = Data(repeating: 2, count: 32), drandRound = Data(count: 8)
        try A.advanceEpochPresent(lk: lk, epochKey: epochKey, drandRound: drandRound)
        try B.advanceEpochPresent(lk: lk, epochKey: epochKey, drandRound: drandRound)
        let beacon = Data("beacon-r1".utf8)
        let (ap, apub) = try A.recognitionContribution(beacon: beacon)
        let (bp, bpub) = try B.recognitionContribution(beacon: beacon)
        let tA = A.establishTunnel(myPriv: ap, myPub: apub.publicKey, their: bpub, beacon: beacon)
        let tB = B.establishTunnel(myPriv: bp, myPub: bpub.publicKey, their: apub, beacon: beacon)
        XCTAssertEqual(tA, tB)
        XCTAssertNotEqual(try A.currentSession().key, try B.currentSession().key)

        // Mode 1
        let m1 = try Tunnel.seal(Data("hello B".utf8), mode: .normal, key: tA)
        XCTAssertEqual(try Tunnel.open(m1, key: tB), Data("hello B".utf8))

        // Mode 2
        let comp = Data("epoch-component".utf8)
        let m2 = try Tunnel.seal(Data("eyes only".utf8), mode: .verifiedHuman, key: tA,
                                 beaconComponent: comp, recipientEnclavePublic: B.attestation.enclaveKey.publicKey)
        let gate = LivenessGate(); for (_, l) in Synthetic.liveStream(40) { gate.update(pSGivenLive: l.0, pSGivenNotLive: l.1) }
        let pole = gate.state(sensorDigest: Data("d".utf8), drandRound: drandRound)
        let out = try Tunnel.open(m2, key: tB, currentBeaconComponent: comp, attestationProvider: { B.attestation.attest(pole) })
        XCTAssertEqual(out, Data("eyes only".utf8))
        XCTAssertThrowsError(try Tunnel.open(m2, key: tB, currentBeaconComponent: nil, attestationProvider: { B.attestation.attest(pole) }))
        XCTAssertThrowsError(try Tunnel.open(m2, key: tB, currentBeaconComponent: comp, attestationProvider: { nil }))
    }
}
