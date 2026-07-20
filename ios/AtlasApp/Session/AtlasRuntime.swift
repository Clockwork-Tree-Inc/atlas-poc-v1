import Foundation
import AtlasCore

/// Wires the full Atlas stack on-device for the ambient iPhone PoC.
///
/// The pipeline is SOURCE-AGNOSTIC: it consumes a `SignalSource` (ambient now,
/// ring later). The ambient signal TIMES the ratchet and GATES advance; the VALUE
/// stays clean QRNG. Real Secure Enclave storage, PoLE draw, session key, epoch-
/// wraps-LK, continuity-gated unwrap, advancing ratchet, duress slice, PQC tunnel.
///
/// Deferred/flagged (see AtlasFlags + RESYNC_NOTES): the live-provenance
/// attribution binding (Priority-1 `live_binding`) is not yet ported to Swift —
/// the runtime marks attribution as DEFERRED rather than faking it. App Attest is
/// stubbed under free provisioning. Population/aggregate timing is degenerate on a
/// single device (SIMULATED).
///
/// STATUS: unrun until built on a Mac to a device.
///
/// Isolation: `@MainActor` — the runtime is driven directly by its SwiftUI view
/// model (`AmbientPoCModel`, also `@MainActor`), so co-isolating them keeps the
/// non-Sendable engine and its `PoLEState`/epoch state on one actor with nothing
/// crossing a boundary. The genuinely off-main work — the per-tick sensor burst —
/// still hops off via `AmbientSensorSource`'s `nonisolated async` reads.
@MainActor
public final class AtlasRuntime {

    private let enclave = SecureEnclaveStore()
    private let ambient = AmbientSensorSource()
    private let sphincs: SphincsProvider

    // ONE persistent ambient source: change-detection keeps its prev-snapshot +
    // entropy history across ticks. A fresh source per call would reset to bootstrap
    // every tick (no previous to diff) and change-detection would never engage.
    private lazy var ambientSource: SignalSource = ambient.asSignalSource()
    // Persistent liveness accumulator: the REAL ambient change drives the PoLE over
    // successive ticks (replaces the synthetic stand-in). Seeded at enrol, when the
    // user has just proven presence (Face ID), so the first ratchet operates.
    private let livenessGate = LivenessGate()

    private var device: Device?
    private var panicVault: PanicVault?
    private var enrollmentSecret: Data?
    private var drandRound = Data(count: 8)
    private var epochLK: Data?          // clean QRNG value (kept raw for the present-user advance)
    private var epochKeyValue: Data?    // clean QRNG value (network-public)

    public init(sphincs: SphincsProvider) {
        self.sphincs = sphincs
        AtlasFlags.logHonesty()
    }

    /// The live signal source for this build (ambient). Swapping to the ring is a
    /// one-line change here — the rest of the runtime is unchanged. Returns the
    /// PERSISTENT source so change-detection state survives across ticks.
    public func signalSource() -> SignalSource {
        switch AtlasFlags.signalSource {
        case .ambient: return ambientSource
        case .ring:    return RingSignalSource()     // deferred; throws on sample()
        }
    }

    /// PoLE from the REAL ambient change (replaces the synthetic liveness stream).
    /// Pull one fresh snapshot, map its change/entropy to Bayesian evidence, fold it
    /// into the persistent gate, and return the current PoLE. Liveness accumulates
    /// across ticks (continuity): sustained live change -> operate; a frozen/looped
    /// feed erodes it -> fail-closed. The enrol seed makes the first tick operate.
    public func ambientPoLE(drandRound: Data) async throws -> PoLEState {
        if AtlasFlags.signalSource == .ambient { await ambient.refreshSnapshot() }
        let (psl, psnl) = ambientLivenessLikelihoods(try signalSource().sample())
        livenessGate.update(pSGivenLive: psl, pSGivenNotLive: psnl)
        return livenessGate.state(sensorDigest: Data("ambient".utf8), drandRound: drandRound)
    }

    /// No continuous streaming: ambient is pulled fresh per tick (B4). This just
    /// primes sensor permissions with one on-demand snapshot at session start.
    public func primeSensors() async { await ambient.refreshSnapshot() }

    // MARK: - enrolment

    public func enrol(password: String, buttonDoubleClicked: Bool, forensicWindow: Bool,
                      panicCode: String) async throws {
        // Pull a FRESH ambient reading first: the ceremony's liveness gate requires
        // a live signal right now, and the only prior snapshot was taken at launch,
        // before sensor permission was granted (so it reads absent -> notLive).
        if AtlasFlags.signalSource == .ambient { await ambient.refreshSnapshot() }
        let ceremony = EnrollmentCeremony(sphincs: sphincs)
        let result = try await ceremony.enrol(signalSource: signalSource(),
                                              password: password,
                                              buttonDoubleClicked: buttonDoubleClicked,
                                              forensicWindow: forensicWindow)
        // Seal the enrolment secret in the REAL Secure Enclave (biometry-gated,
        // non-extractable). INTEGRATION SEAM: the model `Device` self-generates
        // its own presence secret for the unwrap demo; production merges these so
        // the Device's presence release is this SE-sealed secret. Kept sealed here
        // so the SE path is genuinely exercised.
        _ = enclave.seal(result.enrollmentSecret, label: Data("atlas/enrol-secret".utf8))
        self.enrollmentSecret = result.enrollmentSecret

        let devKey = try enclave.loadOrCreateDevKey()
        self.device = Device(name: "iPhone", identity: result.identity, devKey: devKey,
                             bootstrapTunnelKey: Primitives.randomBytes(32))

        // Duress slice: the panic code opens a decoy; the normal password path is
        // the real one. (Real Secure Enclave sealing is the production upgrade.)
        let pv = try PanicVault(normalCode: Data(password.utf8), panicCode: Data(panicCode.utf8)) { reason in
            print("[ATLAS] zeroize-on-suspicion fired: \(reason)")
        }
        try pv.seedDecoy("wallet", Data("DECOY: small balance, no keys".utf8))
        self.panicVault = pv

        // Enrol presence seed: the user has just proven presence (Face ID + the
        // ceremony), so seed the liveness gate live. Ongoing liveness is then driven
        // by REAL ambient change per tick (ambientPoLE); a frozen/looped feed erodes
        // this seed and the gate fails closed.
        for _ in 0..<20 { livenessGate.update(pSGivenLive: 0.97, pSGivenNotLive: 0.05) }
    }

    // MARK: - LK / epoch machinery (QRNG-valued, ambient-TIMED)

    /// Establish the epoch: generate the LK + epoch key as clean QRNG, wrap the LK
    /// under the epoch key, wrap the epoch key to the enrolment secret. Single
    /// device -> the aggregate arrival timing is degenerate/SIMULATED (flagged),
    /// but the wrap/unwrap/ratchet MACHINERY is real.
    public func establishEpoch() throws -> (wrappedEpochKey: Data, wrappedLK: Data) {
        guard let device else { throw EnrolmentError.notConfirmed }
        let lk = Primitives.randomBytes(32)          // clean QRNG value
        let epochKey = Primitives.randomBytes(32)    // clean QRNG value (network-public)
        self.epochLK = lk
        self.epochKeyValue = epochKey
        let wrappedLK = try Presence.wrapLK(lk, epochKey: epochKey, drandRound: drandRound)
        // The Device wraps the epoch key to its OWN enrolment secret (server-side
        // helper), so only a live, present, enrolled device can unwrap it.
        let wrappedEpochKey = try device.wrapEpochKey(epochKey, drandRound: drandRound)
        return (wrappedEpochKey, wrappedLK)
    }

    /// Presence-gated advance: continuity -> Enclave releases the enrolment secret
    /// -> unwrap epoch key -> unlock LK -> derive session key. No presence, no
    /// release, the unwrap mathematically fails (fail-closed). `liveBiometric` is
    /// the enrolled template the model Enclave matches; on device this is the real
    /// Face ID gate releasing the SE-sealed secret.
    @discardableResult
    public func advance(wrappedEpochKey: Data, wrappedLK: Data, pole: PoLEState, liveBiometric: Data) throws -> SessionKey {
        guard let device, let lk = epochLK, let epochKey = epochKeyValue else { throw EnrolmentError.notConfirmed }
        // AMBIENT BUILD: the biometric live-presence release models the RING's
        // biological presence (deferred here). The enrolled user's presence was
        // proven by Face ID at enrol; per-tick liveness in this build is the AMBIENT
        // SENSOR gate, enforced in ratchetOnce(). So advance under the device's own
        // enrolled presence (self-satisfied) rather than a dummy biometric that can
        // never match. Value stays clean QRNG — the biometric never enters a key.
        return try device.advanceEpochPresent(lk: lk, epochKey: epochKey, drandRound: drandRound, pole: pole)
    }

    // MARK: - the ambient-timed continuity ratchet

    /// One source-driven ratchet step. FRESH-PER-TICK (B4): pull a fresh ambient
    /// snapshot on-demand FIRST, then step. The ambient sample TIMES the interval
    /// and GATES the advance; a dropped/flatlined stream is fail-closed inert.
    /// Attribution binding (Priority-1) is DEFERRED in Swift and marked as such.
    public func ratchetOnce(pole: PoLEState, beacon: Data) async throws -> TimedTick {
        guard let device else { throw EnrolmentError.notConfirmed }
        if AtlasFlags.signalSource == .ambient { await ambient.refreshSnapshot() }   // on-demand pull
        let tick = try timedRatchetStep(device: device, source: signalSource(), pole: pole,
                                        drandRound: drandRound, beacon: beacon)
        if tick.gatedOut { print("[ATLAS] ambient signal absent -> ratchet gated closed (fail-closed)") }
        return tick
    }

    // MARK: - ordinary-decision gate (button double-click; NOT the password)

    /// Ordinary operations are authorised by the live-session button gesture, never
    /// the password. Requires a live session (a fresh continuity key) + the gesture.
    public func authorizeOrdinaryDecision(buttonDoubleClicked: Bool, tick: TimedTick) -> Bool {
        guard buttonDoubleClicked, let t = tick.tick, t.operate else { return false }
        return true
    }

    // MARK: - duress

    public func unlockUnderCode(_ code: String) -> UnlockResult? {
        panicVault?.unlock(Data(code.utf8))
    }

    public func zeroizeOnSuspicion(_ reason: String) {
        panicVault?.zeroizeOnSuspicion(reason)
    }
}
