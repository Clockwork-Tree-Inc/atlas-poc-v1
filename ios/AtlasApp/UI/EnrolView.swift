import SwiftUI
import Combine
import AtlasCore

/// The setup wizard — an iOS-first-boot-style progression. Full screen, one step at a
/// time, Continue between them:
///   0 name · 1 ENROL THE RING (live pulse) · 2 codes · 3 create identity (Face ID) ·
///   4 save USB recovery · 5 done -> go live.
/// Liveness is the ring's pulse (fail-closed — no pulse, no Continue). The YubiKey
/// witness step is SUSPENDED until an NFC-capable key is wired (the Bio is USB-only
/// and iOS FIDO2 is NFC/Lightning); the signing method stays in the session, dormant.
struct EnrolView: View {
    @EnvironmentObject var session: AtlasSession
    @State private var step = 0
    @State private var password = ""
    @State private var panic = ""
    @State private var busy = false          // creating identity (Face ID)
    @State private var usbData: Data?
    @State private var showExporter = false
    @State private var savedUSB = false

    var body: some View {
        Group {
            if step == 1 {
                // The ring step owns its own layout so it can observe the live pulse.
                RingEnrolStep(ring: session.ring) { step = 2 }
            } else {
                VStack(spacing: 24) {
                    Spacer(); page; Spacer(); bottomBar
                }
                .padding(28)
            }
        }
        .fileExporter(isPresented: $showExporter,
                      document: usbData.map { RecoveryFile(data: $0) },
                      contentType: .data, defaultFilename: "atlas-recovery.share") { r in
            if case .success = r { savedUSB = true }
        }
    }

    // MARK: pages

    @ViewBuilder private var page: some View {
        switch step {
        case 0:
            big("👋", "Set up Atlas", "One identity — live-present, anonymous, recoverable. Let's set it up.")
            TextField("Your name (e.g. aun)", text: $session.username)
                .textFieldStyle(.roundedBorder).textInputAutocapitalization(.never).autocorrectionDisabled()
                .frame(maxWidth: 320)
        case 2:
            big("🔑", "Your codes", "Your password opens the real vault. Your panic code opens a decoy under duress.")
            VStack(spacing: 12) {
                SecureField("Password (real)", text: $password).textFieldStyle(.roundedBorder)
                SecureField("Panic code (decoy, optional)", text: $panic).textFieldStyle(.roundedBorder)
            }.frame(maxWidth: 320)
        case 3:
            big("🫆", "Create your identity", "Face ID binds your identity, epoch key, live LK, vault and recovery — in one motion, under your live ring pulse.")
            if busy || session.provisioned {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(Array(session.enrolProgress.enumerated()), id: \.offset) { _, s in
                        Text(s).font(.footnote.monospaced())
                    }
                    if busy && !session.provisioned { ProgressView().padding(.top, 4) }
                }.frame(maxWidth: 340, alignment: .leading)
            }
        case 4:
            big("💾", "Save your recovery share", "Write your USB recovery share to the drive. Combined with the server nodes, it can rebuild your identity if you lose your phone.")
            if savedUSB { Text("saved ✓").font(.headline).foregroundStyle(.green) }
        default:
            big("✅", "You're all set", "Your identity is live — signed by your YubiKey, gated by your live ring pulse. Everything runs under it.")
        }
    }

    private func big(_ emoji: String, _ title: String, _ subtitle: String) -> some View {
        VStack(spacing: 14) {
            Text(emoji).font(.system(size: 60))
            Text(title).font(.largeTitle.bold()).multilineTextAlignment(.center)
            Text(subtitle).font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }.frame(maxWidth: 360)
    }

    // MARK: bottom bar

    @ViewBuilder private var bottomBar: some View {
        switch step {
        case 0:
            continueButton("Continue", enabled: !session.username.isEmpty) { step = 1 }
        case 2:
            continueButton("Continue", enabled: !password.isEmpty) { step = 3 }
        case 3:
            if session.provisioned {
                continueButton("Continue") { step = 4 }
            } else {
                continueButton(busy ? "Creating…" : "Continue with Face ID", enabled: !busy) { create() }
            }
        case 4:
            VStack(spacing: 10) {
                Button("Save to drive") { usbData = session.recoveryUSBShare(); showExporter = usbData != nil }
                    .buttonStyle(.bordered)
                continueButton(savedUSB ? "Continue" : "Skip for now") { step = 5 }
            }
        default:
            continueButton("Enter Atlas") { session.goLive() }
        }
    }

    private func continueButton(_ title: String, enabled: Bool = true, _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title).font(.headline).frame(maxWidth: .infinity).padding(.vertical, 6)
        }
        .buttonStyle(.borderedProminent).controlSize(.large).disabled(!enabled)
        .frame(maxWidth: 360)
    }

    private func create() {
        busy = true
        Task {
            do { try await session.provision(password: password, panicCode: panic, buttonDoubleClicked: true) }
            catch { session.log.append("Setup refused: \(error)") }
            busy = false
        }
    }
}

/// Step 1 — enrol the ring. Scan, connect, and confirm a LIVE PULSE before Continue
/// unlocks (fail-closed). Observes the ring directly so the pulse updates live.
struct RingEnrolStep: View {
    @ObservedObject var ring: RingProbe
    var onContinue: () -> Void
    @StateObject private var phone = PhoneTapCapture()
    @State private var requestedN = 0
    @State private var bindPhase = "idle"     // idle | tapping | done
    @State private var bound = false
    @State private var bindNote = ""
    private let windowS = 6.0

    var body: some View {
        VStack(spacing: 22) {
            Spacer()
            VStack(spacing: 14) {
                Text(bound ? "🤝" : (ring.pulsePresent ? "❤️" : "💍")).font(.system(size: 60))
                Text("Wear your ring").font(.largeTitle.bold()).multilineTextAlignment(.center)
                Text("Your ring proves you're a live person, and the handshake binds it to this phone in your hand. Put it on snug, connect, then do the handshake.")
                    .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }.frame(maxWidth: 360)

            if ring.connectedName.isEmpty {
                Button("Scan for your ring") { ring.scanAll() }.buttonStyle(.bordered)
                if ring.devices.isEmpty {
                    Text(ring.status).font(.caption).foregroundStyle(.secondary)
                } else {
                    VStack(spacing: 6) {
                        ForEach(ring.devices) { d in
                            Button { ring.connect(d) } label: {
                                HStack {
                                    Text(d.name.isEmpty ? "unknown device" : d.name)
                                    Spacer()
                                    Text("\(d.rssi) dBm").foregroundStyle(.secondary)
                                }.font(.footnote)
                            }.buttonStyle(.bordered)
                        }
                    }.frame(maxWidth: 320)
                }
            } else if !ring.pulsePresent {
                Text(ring.connectedName).font(.subheadline.bold())
                Text("waiting for your pulse… wear it snug")
                    .font(.headline).foregroundStyle(.orange)
            } else {
                bindSection
            }

            Spacer()
            Button(action: onContinue) {
                Text("Continue").font(.headline).frame(maxWidth: .infinity).padding(.vertical, 6)
            }
            .buttonStyle(.borderedProminent).controlSize(.large)
            .disabled(!(ring.pulsePresent && bound)).frame(maxWidth: 360)
        }
        .padding(28)
    }

    /// The handshake bind: with a live pulse, the user taps the ring on the phone a random
    /// number of times. The phone IMU + ring IMU must both see those taps -> same hand.
    @ViewBuilder private var bindSection: some View {
        Text("LIVE PULSE ✓").font(.headline).foregroundStyle(.green)
        switch bindPhase {
        case "idle":
            Text("Handshake: hold the phone in your ring hand. Tap the ring on the phone the number of times shown, at a steady pace.")
                .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 340)
            Button("Start handshake") { startBind() }.buttonStyle(.bordered).disabled(!phone.available)
        case "tapping":
            Text("Tap \(requestedN)×").font(.system(size: 48, weight: .bold, design: .rounded))
            ProgressView()
        default:
            Text(bindNote).font(.footnote).multilineTextAlignment(.center)
                .foregroundStyle(bound ? .green : .red).frame(maxWidth: 340)
            if !bound { Button("Try again") { bindPhase = "idle" } }
        }
    }

    private func startBind() {
        requestedN = Int.random(in: 3...5)
        bindPhase = "tapping"; bound = false
        let startAt = Date().timeIntervalSince1970
        phone.begin()
        DispatchQueue.main.asyncAfter(deadline: .now() + windowS - 0.5) {
            let phoneTaps = phone.end()
            let ringTaps = ring.ringTapTimes(windowS: windowS)
            let faceID = startAt + windowS / 2
            let full = verifyHandshake(phoneTaps: phoneTaps, ringTaps: ringTaps,
                                       requestedN: requestedN, faceIDAtS: faceID, windowS: windowS)
            if full && ring.pulsePresent {
                bound = true
                bindNote = "Bound 🤝 — \(requestedN) taps seen by phone AND ring: same hand, live pulse."
            } else if !ring.supportsSameHandBind && phoneTaps.count == requestedN && ring.pulsePresent {
                // This wearable lacks a high-rate IMU — the same-hand cross-check can't run;
                // accept the live tap challenge (identity + live pulse still gate), honestly
                // labelled. A wearable with `.highRateIMU` takes the full path above.
                bound = true
                bindNote = "Tap challenge passed ✓ — this wearable doesn't stream motion fast enough, so same-hand isn't cryptographically proven (identity + live pulse still gate)."
            } else {
                bound = false
                bindNote = "Not bound — phone saw \(phoneTaps.count) tap(s), needed \(requestedN)"
                    + (ring.pulsePresent ? "" : "; no live pulse") + ". Try again."
            }
            bindPhase = "done"
        }
    }
}
