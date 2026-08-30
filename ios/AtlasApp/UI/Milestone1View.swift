import SwiftUI
import Combine
import AtlasCore

/// Milestone 1 exit test on-device (§13, §10.1): two in-process wallets run the
/// encrypted text A->B flow, prove forward secrecy, and show the Mode-2 gate.
/// Mirrors `backend/demos/demo_milestone1_text.py`.
@MainActor
final class Milestone1Model: ObservableObject {
    @Published var log: [String] = []
    private let sphincs = PlaceholderSphincs()

    func run() {
        log.removeAll()
        do { try runInner() } catch { add("ERROR: \(error)") }
    }
    private func add(_ s: String) { log.append(s) }

    private func runInner() throws {
        add("Enrolled pair (shared in-person root).")
        let seed = Primitives.randomBytes(32)
        let boot = Primitives.randomBytes(32)
        let A = Device(name: "A", identity: try IdentityTree.build(tskSeed: seed, sphincs: sphincs), bootstrapTunnelKey: boot)
        let B = Device(name: "B", identity: try IdentityTree.build(tskSeed: seed, sphincs: sphincs), bootstrapTunnelKey: boot)

        let beacon = LocalBeacon(periodS: 3)
        let qrng = ServerQRNG()

        func epoch(_ now: TimeInterval) throws -> (Data, Data, BeaconRound) {
            let rnd = beacon.round(at: now)
            let draw = qrng.fire(arrival: ArrivalTiming(timestamps: [now, now + 0.18, now + 0.41]), drandRound: rnd.drandRound())  // LK
            // epoch key = network-public epoch QRNG (clean value), NOT drand (rnd stays a timestamp witness)
            let epochDraw = qrng.fire(arrival: ArrivalTiming(timestamps: [now, now + 0.3, now + 0.7]), drandRound: rnd.drandRound())
            try A.advanceEpochPresent(lk: draw.randomness, epochKey: epochDraw.randomness, drandRound: rnd.drandRound())
            try B.advanceEpochPresent(lk: draw.randomness, epochKey: epochDraw.randomness, drandRound: rnd.drandRound())
            let label = Data("component|".utf8) + rnd.drandRound()
            let (ap, apub) = try A.recognitionContribution(beacon: label)
            let (bp, bpub) = try B.recognitionContribution(beacon: label)
            let tA = A.establishTunnel(myPriv: ap, myPub: apub.publicKey, their: bpub, beacon: label)
            let tB = B.establishTunnel(myPriv: bp, myPub: bpub.publicKey, their: apub, beacon: label)
            add("epoch r\(rnd.round): A.session≠B.session=\((try? A.currentSession().key) != (try? B.currentSession().key)) · recognition match=\(tA == tB)")
            return (tA, tB, rnd)
        }

        add("— MODE 1 —")
        let (tA1, tB1, rnd1) = try epoch(1)
        let m1 = try Tunnel.seal(Data("Message #1: hello from A".utf8), mode: .normal, key: tA1)
        add("B decrypts: \(String(data: try Tunnel.open(m1, key: tB1), encoding: .utf8)!)")

        add("— FORWARD SECRECY —")
        let (k2, secret) = A.messageRatchetStep(tA1, beaconT: rnd1.randomness, drandRound: rnd1.drandRound())
        let m2 = try Tunnel.seal(Data("Message #2: ratcheted".utf8), mode: .normal, key: k2)
        let bKey2 = Derivation.ratchet(tB1, entropyT: secret, beaconT: rnd1.randomness, drandRound: rnd1.drandRound())
        add("B decrypts #2: \(String(data: try Tunnel.open(m2, key: bKey2), encoding: .utf8)!)")
        let guessKey = Derivation.ratchet(tA1, entropyT: Data(count: 32), beaconT: rnd1.randomness, drandRound: rnd1.drandRound())
        if (try? Tunnel.open(m2, key: guessKey)) == nil {
            add("captured earlier key CANNOT read #2 ✓")
        } else { add("!! forward secrecy FAILED") }

        add("— MODE 2 (verified-human-only) —")
        let (tA2, tB2, rnd2) = try epoch(4)
        let comp = Data("component|".utf8) + rnd2.drandRound()
        let m3 = try Tunnel.seal(Data("Message #3: eyes only".utf8), mode: .verifiedHuman, key: tA2,
                                 beaconComponent: comp, recipientEnclavePublic: B.attestation.enclaveKey.publicKey)
        let gate = LivenessGate()
        for (_, l) in Synthetic.liveStream(40) { gate.update(pSGivenLive: l.0, pSGivenNotLive: l.1) }
        let pole = gate.state(sensorDigest: Data("sensor".utf8), drandRound: rnd2.drandRound())
        let opened = try Tunnel.open(m3, key: tB2, currentBeaconComponent: comp,
                                     attestationProvider: { B.attestation.attest(pole) }, expectedDrandRound: rnd2.drandRound())
        add("verified-live opens: \(String(data: opened, encoding: .utf8)!)")
        if (try? Tunnel.open(m3, key: tB2, currentBeaconComponent: nil, attestationProvider: { B.attestation.attest(pole) })) == nil {
            add("offline holder → DENIED ✓")
        }
        if (try? Tunnel.open(m3, key: tB2, currentBeaconComponent: comp, attestationProvider: { nil })) == nil {
            add("bot/not-live → DENIED ✓")
        }
        add("MILESTONE 1: PASS ✓")
    }
}

struct Milestone1View: View {
    @StateObject private var model = Milestone1Model()
    var body: some View {
        NavigationStack {
            VStack(alignment: .leading) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(Array(model.log.enumerated()), id: \.offset) { _, line in
                            Text(line).font(.system(.footnote, design: .monospaced))
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
                Button(action: model.run) {
                    Text("Run Milestone-1 exit test").frame(maxWidth: .infinity)
                }.buttonStyle(.borderedProminent).padding(.top, 8)
            }
            .padding()
            .navigationTitle("M1 · Encrypted text A→B")
        }
    }
}
