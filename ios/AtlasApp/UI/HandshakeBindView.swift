import SwiftUI
import CoreMotion
import AtlasCore

/// Captures the PHONE's accelerometer tap impulses during the bind window (100 Hz),
/// returning tap onset times (deviation from 1 g rest, threshold-cross + refractory).
@MainActor
final class PhoneTapCapture: ObservableObject {
    private let motion = CMMotionManager()
    private var samples: [(t: TimeInterval, mag: Double)] = []
    @Published private(set) var capturing = false

    var available: Bool { motion.isAccelerometerAvailable }

    func begin() {
        guard motion.isAccelerometerAvailable else { return }
        samples = []; capturing = true
        motion.accelerometerUpdateInterval = 1.0 / 100.0
        motion.startAccelerometerUpdates(to: .main) { [weak self] data, _ in
            guard let self, let a = data?.acceleration else { return }
            let mag = (a.x * a.x + a.y * a.y + a.z * a.z).squareRoot()
            self.samples.append((Date().timeIntervalSince1970, abs(mag - 1.0)))   // deviation from 1 g
        }
    }

    func end(threshold: Double = 0.3, refractoryS: Double = 0.15) -> [Double] {
        motion.stopAccelerometerUpdates(); capturing = false
        guard samples.count > 1 else { return [] }
        var taps: [Double] = []; var last = -1e9
        for i in 1..<samples.count where samples[i].mag >= threshold && samples[i - 1].mag < threshold && (samples[i].t - last) >= refractoryS {
            taps.append(samples[i].t); last = samples[i].t
        }
        return taps
    }
}

/// The enrolment HANDSHAKE BIND, device-testable: the phone shows a random N; you tap the
/// ring on the phone N times; the phone IMU and the ring IMU must each register N taps that
/// co-occur (same hand), and the pulse must be live. Uses `verifyHandshake` from AtlasCore.
struct HandshakeBindView: View {
    @ObservedObject var ring: RingProbe
    @StateObject private var phone = PhoneTapCapture()
    @State private var requestedN = 0
    @State private var phase = "idle"        // idle | tapping | done
    @State private var result: String?
    @State private var passed = false
    private let windowS = 6.0

    var body: some View {
        NavigationStack {
            Form {
                Section("Handshake bind (device test)") {
                    Text("Ring on, phone in the SAME hand. Tap the ring on the phone the number of times shown, at a steady pace. Both the phone and the ring must see the same taps — that proves they're on one hand.")
                        .font(.caption).foregroundStyle(.secondary)
                    if !phone.available {
                        Label("No accelerometer on this device", systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                    }
                    if !ring.isStreamingAccel {
                        Label("Ring isn't streaming motion — the R10's accel stream is intermittent, so the same-hand check can't run on it. (Works on an IMU-streaming ring.)", systemImage: "info.circle")
                            .font(.caption).foregroundStyle(.orange)
                    }
                }
                Section {
                    if phase == "idle" {
                        Button("Start bind") { start() }.buttonStyle(.borderedProminent)
                            .disabled(!phone.available)
                    } else if phase == "tapping" {
                        VStack(spacing: 8) {
                            Text("Tap \(requestedN)×").font(.system(size: 44, weight: .bold, design: .rounded))
                            ProgressView()
                            Text("tapping window…").font(.caption).foregroundStyle(.secondary)
                        }.frame(maxWidth: .infinity)
                    } else {
                        Text(result ?? "")
                            .font(.headline)
                            .foregroundStyle(passed ? .green : .red)
                        Button("Try again") { phase = "idle"; result = nil }
                    }
                }
            }
            .navigationTitle("Handshake bind")
        }
    }

    private func start() {
        requestedN = Int.random(in: 3...5)
        phase = "tapping"; result = nil
        let startAt = Date().timeIntervalSince1970
        phone.begin()
        // Give the user a fixed window to produce the taps, then verify.
        DispatchQueue.main.asyncAfter(deadline: .now() + windowS - 0.5) {
            let phoneTaps = phone.end()
            let ringTaps = ring.ringTapTimes(windowS: windowS)
            // faceIDAt = the window centre (in the full wizard this is the real Face ID instant)
            let faceID = startAt + windowS / 2
            let ok = verifyHandshake(phoneTaps: phoneTaps, ringTaps: ringTaps,
                                     requestedN: requestedN, faceIDAtS: faceID, windowS: windowS)
            passed = ok && ring.pulsePresent
            if passed {
                result = "BOUND ✓ — \(requestedN) taps on phone + ring, same hand, live pulse."
            } else {
                result = "not bound — phone \(phoneTaps.count) tap(s), ring \(ringTaps.count) tap(s), needed \(requestedN) on both"
                    + (ring.pulsePresent ? "" : ", no live pulse")
            }
            phase = "done"
        }
    }
}
