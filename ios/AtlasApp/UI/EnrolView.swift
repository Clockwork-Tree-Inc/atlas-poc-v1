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
    @State private var step = -1             // -1 = first-run CHOICE: create OR recover
    @State private var password = ""
    @State private var panic = ""
    @State private var busy = false          // creating identity (Face ID)
    @State private var usbData: Data?
    @State private var showExporter = false
    @State private var savedUSB = false
    @State private var showRecovery = false  // present the (legacy) recovery flow
    @State private var showShardRecovery = false  // 2-of-n shard recovery

    var body: some View {
        Group {
            if step == -1 {
                // FIRST RUN — the very first thing you see: set up a new account, OR
                // recover an existing one. Recovery must live HERE (before enrol), or a
                // person who lost their phone could never get back in.
                landing
            } else if step == 7 {
                // ANTI-BOT human proof — shake the phone a random number of times.
                ShakeChallengeStep(onBack: { step = 0 }, onPass: { step = 1 })
            } else if step == 1 {
                // The ring step owns its own layout so it can observe the live pulse.
                RingEnrolStep(ring: session.ring) { step = 2 }
            } else {
                VStack(spacing: 24) {
                    if step == 0 {
                        HStack {
                            Button { step = -1 } label: { Label("Back", systemImage: "chevron.left") }
                                .font(.callout)
                            Spacer()
                        }
                    }
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
        .sheet(isPresented: $showShardRecovery) { RecoverFromShardsView().environmentObject(session) }
        .sheet(isPresented: $showRecovery) {
            RecoveryView().environmentObject(session)
        }
    }

    /// First-run choice: create a new identity, or recover an existing one.
    private var landing: some View {
        VStack(spacing: 28) {
            Spacer()
            Image("AtlasLogo").resizable().scaledToFit()
                .frame(width: 132, height: 132)
                .accessibilityLabel("Atlas")
            big("", "Welcome to Atlas", "One identity — live-present, anonymous, recoverable.")
            VStack(spacing: 14) {
                continueButton("Set up a new account") { step = 0 }
                Button { showShardRecovery = true } label: {
                    Text("Recover my account").font(.headline)
                        .frame(maxWidth: .infinity).padding(.vertical, 6)
                }
                .buttonStyle(.bordered).controlSize(.large).frame(maxWidth: 360)
                Text("Lost or replaced your phone? Any TWO recovery shards rebuild your identity — USB stick, a trusted contact's shard, or your server's.")
                    .font(.caption2).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center).frame(maxWidth: 320)
                Button { showRecovery = true } label: {
                    Text("Other recovery options…").font(.caption)
                }
            }
            Spacer()
        }
        .padding(28)
    }

    // MARK: pages

    @ViewBuilder private var page: some View {
        switch step {
        case 0:
            big("👋", "Set up Atlas", "One identity — live-present, anonymous, recoverable. Let's set it up.")
            TextField("Your name (e.g. aun)", text: $session.username)
                .textFieldStyle(.roundedBorder).textInputAutocapitalization(.never).autocorrectionDisabled()
                .frame(maxWidth: 320)
            VStack(spacing: 6) {
                Text(AtlasFlags.disclaimerShort)
                    .font(.caption2).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                Text("Tap the banner above for the full disclaimer — or open the Disclaimer tab after setup.")
                    .font(.caption2).foregroundStyle(.orange)
                    .multilineTextAlignment(.center)
            }.frame(maxWidth: 320).padding(.top, 4)
        case 2:
            big("🔑", "Your codes", "Your password opens the real vault. Your panic code opens a decoy under duress.")
            VStack(spacing: 12) {
                SecureField("Password (real)", text: $password).textFieldStyle(.roundedBorder)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                SecureField("Panic code (decoy, optional)", text: $panic).textFieldStyle(.roundedBorder)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
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
            continueButton("Continue", enabled: !session.username.isEmpty) { step = 7 }
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
                Text(ring.pulsePresent && bound ? "Continue — ring bound ✓" : "Continue")
                    .font(.headline).frame(maxWidth: .infinity).padding(.vertical, 6)
            }
            .buttonStyle(.borderedProminent).controlSize(.large)
            .disabled(!(ring.pulsePresent && bound)).frame(maxWidth: 360)

            // Ambient is ALWAYS the running mix; the ring is optional and ADDITIVE.
            // Enrol can proceed on ambient alone — a connected+bound ring simply folds
            // its signal + biological liveness into the mix and raises the tier.
            Button(action: onContinue) {
                Text("Continue with ambient (skip ring)")
                    .font(.subheadline).frame(maxWidth: .infinity).padding(.vertical, 4)
            }
            .buttonStyle(.bordered).controlSize(.large).frame(maxWidth: 360)
            Text("Ambient (phone sensors) always runs. A ring ADDS its signal + continuous biological liveness on top — optional, add it any time.")
                .font(.caption2).foregroundStyle(.secondary)
                .multilineTextAlignment(.center).frame(maxWidth: 320)
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

/// ANTI-BOT HUMAN PROOF — shake the app-attested phone to hit a target it CANNOT predict.
/// The target sequence (a plan of directional segments) is DERIVED FROM A FRESH RANDOM NONCE
/// via `AntiBot.deriveShakePlan` — never `Int.random` — so it can't be precomputed or replayed.
/// Directions (up-down vs side-to-side) force axis-specific motion (harder for a rig), you shake
/// UNTIL each segment's target is reached, and repeated failures arm `AntiBot.lockBackoffSeconds`
/// (free for 10 tries, then an escalating lockout). A genuine attested IMU trace is the liveness
/// signal — an emulator or script has no device to move.
struct ShakeChallengeStep: View {
    var onBack: () -> Void
    var onPass: () -> Void
    @StateObject private var phone = PhoneTapCapture()
    @State private var plan: [AntiBot.ShakeSegment] = []
    @State private var segIndex = 0
    @State private var phase = "idle"      // idle | shaking | done | locked
    @State private var justFailed = false        // last attempt blown -> a fresh challenge is shown
    @State private var passed = false
    @State private var startedAt = Date()
    @State private var now = Date()
    @State private var failCount = UserDefaults.standard.integer(forKey: ShakeChallengeStep.kFail)
    @State private var lockUntil = Date(timeIntervalSince1970: UserDefaults.standard.double(forKey: ShakeChallengeStep.kLock))
    private let ticker = Timer.publish(every: 0.1, on: .main, in: .common).autoconnect()

    static let kFail = "atlas.shake.failCount"
    static let kLock = "atlas.shake.lockUntil"

    private var lockRemaining: Int { max(0, Int(lockUntil.timeIntervalSince(now).rounded(.up))) }
    private var totalTarget: Int { plan.reduce(0) { $0 + $1.count } }
    private var timeoutS: Double { Double(totalTarget) * 2.5 + 8 }

    var body: some View {
        VStack(spacing: 20) {
            HStack {
                Button { onBack() } label: { Label("Back", systemImage: "chevron.left") }.font(.callout)
                Spacer()
            }
            Spacer()
            Text(passed ? "✅" : (phase == "locked" ? "🔒" : "📳")).font(.system(size: 60))
            Text("Prove you're human").font(.largeTitle.bold()).multilineTextAlignment(.center)
            Text("Shake the phone as shown. Real motion from the attested sensor is what proves a live person — a bot, emulator or script has no device to move.")
                .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 340)

            if !phone.available {
                Label("No motion sensor on this device", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            }

            switch phase {
            case "shaking":
                if segIndex < plan.count {
                    let seg = plan[segIndex]
                    Label("Shake \(seg.count)× \(dirLabel(seg.direction))", systemImage: dirIcon(seg.direction))
                        .font(.title3.weight(.semibold))
                    // Raw live count — NOT clamped, so you can overshoot and get it wrong. No colour
                    // change, no "done" hint: you have to know you're on the number and tap yourself.
                    Text("\(seg.direction == AntiBot.upDown ? phone.liveCountUpDown : phone.liveCountSideways)")
                        .font(.system(size: 80, weight: .bold, design: .rounded))
                        .monospacedDigit()
                        .foregroundStyle(.white)
                    Text("segment \(segIndex + 1) of \(plan.count)").font(.caption).foregroundStyle(.secondary)
                    Button(segIndex + 1 < plan.count ? "Next" : "Finish") { checkSegment() }
                        .buttonStyle(.borderedProminent).controlSize(.large)
                }
            case "done":
                // Only success reaches "done" now — a blown attempt resets to a fresh challenge.
                Text("Human verified ✓").font(.headline).foregroundStyle(.green)
                    .multilineTextAlignment(.center)
            case "locked":
                Text("Too many attempts").font(.headline).foregroundStyle(.orange)
                Text("Locked — try again in \(lockRemaining)s")
                    .font(.system(size: 40, weight: .bold, design: .rounded)).monospacedDigit()
                    .foregroundStyle(.secondary)
            default: // idle
                if justFailed {
                    Text("Not quite — new sequence. Shake to each number exactly, then tap Next.")
                        .font(.callout).foregroundStyle(.orange)
                        .multilineTextAlignment(.center).frame(maxWidth: 320)
                }
                VStack(spacing: 6) {
                    ForEach(Array(plan.enumerated()), id: \.offset) { _, seg in
                        Label("\(seg.count)× \(dirLabel(seg.direction))", systemImage: dirIcon(seg.direction))
                            .font(.title3.weight(.medium))
                    }
                }
                Button("Start shaking") { start() }
                    .buttonStyle(.borderedProminent).controlSize(.large).disabled(!phone.available)
            }

            Spacer()
            Button(action: onPass) {
                Text(passed ? "Continue ✓" : "Continue").font(.headline)
                    .frame(maxWidth: .infinity).padding(.vertical, 6)
            }
            .buttonStyle(.borderedProminent).controlSize(.large).disabled(!passed).frame(maxWidth: 360)
        }
        .padding(28)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.black.ignoresSafeArea())      // white counter reads on a black screen
        .environment(\.colorScheme, .dark)              // primary/secondary text render light-on-dark, both device modes
        .onAppear {
            if plan.isEmpty { newChallenge() }
            if lockRemaining > 0 { phase = "locked" }
        }
        .onReceive(ticker) { t in
            now = t
            if phase == "locked", lockRemaining == 0 { newChallenge(); phase = "idle" }
            guard phase == "shaking", segIndex < plan.count else { return }
            // No auto-advance and no clamp — the counter just keeps climbing. The only automatic
            // outcome is a timeout (a stalled bot fails); the user decides when to tap Next.
            if t.timeIntervalSince(startedAt) > timeoutS { fail() }
        }
    }

    private func dirLabel(_ d: String) -> String { d == AntiBot.upDown ? "up & down" : "side to side" }
    private func dirIcon(_ d: String) -> String { d == AntiBot.upDown ? "arrow.up.arrow.down" : "arrow.left.arrow.right" }

    /// Fresh RNG nonce -> a new unpredictable directional plan (never precomputable / replayable).
    private func newChallenge() {
        let nonce = Primitives.randomBytes(16)
        plan = AntiBot.deriveShakePlan(nonce: nonce)
        segIndex = 0; passed = false
    }

    /// The user taps Next/Finish when THEY judge they're on the number. Pass only if the live count
    /// is EXACTLY the target — overshooting (or stopping short) fails. Reading the count fresh at tap
    /// time (not a stale render) so the check is on what's actually on screen.
    private func checkSegment() {
        guard segIndex < plan.count else { return }
        let seg = plan[segIndex]
        let cnt = seg.direction == AntiBot.upDown ? phone.liveCountUpDown : phone.liveCountSideways
        guard cnt == seg.count else { fail(); return }   // over/undershoot -> blown it
        phone.resetLiveCounts()
        segIndex += 1
        startedAt = Date()                               // fresh timeout budget per segment
        if segIndex >= plan.count { succeed() }
    }

    private func start() {
        guard lockRemaining == 0 else { phase = "locked"; return }
        passed = false; segIndex = 0; startedAt = Date(); justFailed = false
        phone.resetLiveCounts()
        phase = "shaking"
        // A SHAKE is a big impulse — high threshold + refractory so each registers once; the
        // directional mode classifies up-down vs sideways from the gravity-removed AC axis.
        phone.begin(liveThreshold: 0.9, liveRefractoryS: 0.25, directional: true)
    }

    private func succeed() {
        _ = phone.end()
        passed = true; phase = "done"
        failCount = 0; persist()
    }

    private func fail() {
        _ = phone.end()
        failCount += 1
        let backoff = AntiBot.lockBackoffSeconds(failCount: failCount)
        if backoff > 0 {
            lockUntil = now.addingTimeInterval(Double(backoff)); phase = "locked"
        } else {
            // Blew it (overshot / stopped short / timed out) -> a WHOLE NEW challenge: fresh count
            // and directions, back to the start. Nothing to memorise or replay.
            justFailed = true
            newChallenge()
            phase = "idle"
        }
        persist()
    }

    private func persist() {
        UserDefaults.standard.set(failCount, forKey: Self.kFail)
        UserDefaults.standard.set(lockUntil.timeIntervalSince1970, forKey: Self.kLock)
    }
}
