import Foundation

/// Build/runtime flags + honest stand-in markers for the iPhone-only ambient PoC.
///
/// The point of this build: run the FULL crypto/identity/session/duress stack on
/// real Apple hardware, with the phone's ambient multimodal stream standing in
/// for the R10 ring's TIMING/GATING role. Everything else is real. These flags
/// keep every stand-in LOUD so nothing is silently overclaimed.
public enum AtlasFlags {

    /// The live physical timing/gating signal source for this build.
    ///  * `.ambient` — the phone's fused ambient sensors (this build).
    ///  * `.ring`    — the R10 streamed biological signal (later; source swap only).
    public enum SignalSourceKind: String, Sendable { case ambient, ring }
    public static let signalSource: SignalSourceKind = .ambient

    /// Use the microphone as an ambient channel — ADAPTIVELY. The mic is sampled
    /// ONLY when no other audio is playing (`AVAudioSession.isOtherAudioPlaying`
    /// is false); the instant you start music or a call it steps aside and presence
    /// runs on the motion channels (accel/gyro/mag/baro) alone. That way it never
    /// competes for the mic and never drops Bluetooth audio A2DP->HFP. iOS forbids
    /// reading another app's audio output, so we can't fold your music in — quiet =
    /// mic, audio playing = motion-only.
    public static let useAmbientMic = true

    /// App Attest requires a paid Apple Developer account. On free provisioning we
    /// STUB the attest call behind this flag — everything else stays real. Flip to
    /// `false` when building with a paid team to exercise real DeviceCheck attest.
    public static let appAttestStubbed = true

    /// The population/aggregate PoLE-arrival timing is degenerate on a single
    /// device (no cohort). This is expected; we mark it SIMULATED so nobody reads
    /// single-device timing as population-scale behavior.
    public static let aggregateTimingSimulated = true

    /// One honest banner summarising what is real vs stood-in vs stubbed, for the
    /// UI/logs. Update alongside the flags above.
    public static var honestyBanner: [String] {
        var lines = [
            "REAL: Face ID · button gates · password (enrol only) · Secure Enclave · "
            + "PoLE/session/epoch-wrap/ratchet · duress slice · PQC ML-KEM tunnel",
            "STAND-IN: ambient sensors TIME + GATE (ambient-not-biological) — the ring "
            + "signal is the one deferred input; VALUE stays clean QRNG",
        ]
        if appAttestStubbed {
            lines.append("STUBBED: App Attest (no paid account) — device authenticity not proven")
        }
        if aggregateTimingSimulated {
            lines.append("SIMULATED: population/aggregate timing is degenerate on one device")
        }
        return lines
    }

    /// Emit the honesty banner to the log once at startup.
    public static func logHonesty() {
        for line in honestyBanner { print("[ATLAS-HONESTY] \(line)") }
    }
}
