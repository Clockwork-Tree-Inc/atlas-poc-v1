import Foundation
import CryptoKit

/// A wallet/device node — composes its own session key locally (§2, §3, §4).
/// Mirrors `backend/atlas/session/device.py`. Decision #3: the server returns
/// only timed randomness; the device composes its session key locally.

/// Everything needed to compose one epoch's session key (kept for parity with
/// device.py; `advanceEpoch` now takes the WRAPPED wire form, not this).
public struct EpochInputs {
    public let lk: Data          // Living Key — server QRNG timed draw (private beacon)
    public let epochKey: Data    // beacon round randomness (public beacon)
    public let drandRound: Data
    public init(lk: Data, epochKey: Data, drandRound: Data) { self.lk = lk; self.epochKey = epochKey; self.drandRound = drandRound }
}

/// Ratchet refused: no live enrolled presence, so the epoch key could not be
/// unwrapped (fail-closed, §2.3 / FIX #7).
public enum PresenceRequired: Error, Equatable {
    case noLivePresence      // enclave did not release the enrollment secret
    case epochUnwrapFailed   // not the enrolled present device
    case lkUnlockFailed      // epoch key did not unlock the LK
}

/// Result of one independent continuity-ratchet tick (§5.3). `attestation` is nil
/// iff liveness broke at this tick (containment fired, no new key material).
public struct ContinuityTick {
    public let intervalS: Double
    public let continuityKey: Data              // empty when liveness broke this tick
    public let attestation: LivenessAttestation?
    public let operate: Bool
}

public final class Device {
    public let name: String
    public let identity: IdentityTree
    public let devKey: Data
    public private(set) var tunnelKey: Data
    public let attestation: AttestationSubsystem
    /// True iff a bootstrap tunnel key was supplied (§6 in-person ritual). Omitted
    /// -> fresh random root (fail-closed), NOT a public all-zero constant.
    public let bootstrapped: Bool

    private let deviceKeypair: HybridSign.Keypair
    private var session: SessionKey?
    private var prevSessionBytes = Data(repeating: 0, count: 32)

    // Independent local continuity-ratchet clock (~10s ± jitter, §5.3) and the
    // rolling continuity-chain key it advances.
    private let ratchetClock: RatchetClock
    private var continuityKey: Data?

    // Presence enrollment (§2.3 / FIX #7): a shared enrollment secret sealed in the
    // device Secure Enclave, released only on live enrolled presence. The server
    // holds a copy to WRAP epoch keys; the device can only UNWRAP them while the
    // enrolled user is live and present.
    private let enrollmentSecret: Data
    private let enrolledBiometric: Data
    private let presence: EnrolledPresence

    public init(name: String, identity: IdentityTree, devKey: Data? = nil,
                bootstrapTunnelKey: Data? = nil, attestation: AttestationSubsystem? = nil,
                ratchetClock: RatchetClock? = nil, enclave: BiometricEnclave? = nil) {
        self.name = name
        self.identity = identity
        self.devKey = devKey ?? Primitives.randomBytes(32)
        // Device authentication keypair (§2.4 / FIX #6): identification AND
        // authentication by challenge-response. The private half NEVER leaves the
        // device and is NEVER in any key derivation; it only signs fresh server
        // challenges. Freely rotatable (rotate devKey -> new auth key).
        self.deviceKeypair = try! HybridSign.keypair(fromSeed: Primitives.hkdf(ikm: self.devKey, info: Data("atlas/devkey/auth".utf8)))
        // Shared in-person enrolment secret roots the tunnel before the first
        // recognition (§6). SECURITY: omitted -> FAIL CLOSED with a fresh per-device
        // random root (un-bootstrapped pairs do NOT converge), NOT a public all-zero
        // constant (which would make any two un-bootstrapped devices match trivially).
        self.bootstrapped = bootstrapTunnelKey != nil
        self.tunnelKey = bootstrapTunnelKey ?? Primitives.randomBytes(32)
        self.attestation = attestation ?? AttestationSubsystem()
        self.session = nil
        self.prevSessionBytes = Data(repeating: 0, count: 32)
        self.ratchetClock = ratchetClock ?? (try! RatchetClock())
        self.continuityKey = nil
        self.enrollmentSecret = Primitives.randomBytes(32)
        self.enrolledBiometric = Primitives.randomBytes(256)
        self.presence = EnrolledPresence(self.enrollmentSecret, enclave: enclave ?? ModelEnclave(), biometric: self.enrolledBiometric)
        // Wire containment: a liveness break wipes the live session key (§2.2).
        self.attestation.setOnWipe { [weak self] in self?.wipeSession() }
    }

    // -- device-key challenge-response auth (§2.4 / FIX #6) ------------------

    /// The device's PUBLIC auth half (given to the server at enrollment). The
    /// private half never leaves the device.
    public func devicePublic() -> HybridSign.PublicKey { deviceKeypair.publicKey }

    /// Sign a fresh server challenge with the device private half (never
    /// transmitted). Proves possession without revealing the key or entering any
    /// key derivation.
    public func respondToChallenge(_ challenge: Data) throws -> Data {
        try HybridSign.sign(deviceKeypair, challenge)
    }

    // -- session composition (local) ----------------------------------------

    /// Server-side helper: wrap an epoch key to THIS device's enrollment secret
    /// (the server holds a copy from enrollment). Only a live, present, enrolled
    /// device can unwrap it.
    public func wrapEpochKey(_ epochKey: Data, drandRound: Data) throws -> Data {
        try Presence.wrapEpochKey(epochKey, enrollmentSecret: enrollmentSecret, drandRound: drandRound)
    }

    /// Compose this epoch's session key via the full value/timing chain (§2.3):
    ///
    ///     continuity=yes  -> Enclave releases the enrollment secret
    ///                     -> UNWRAP the (public) epoch key
    ///                     -> UNLOCK the (private) LK with that epoch key
    ///                     -> SessKey = HKDF(PoLE_value, LK, epoch_key, prev, ctx).
    ///
    /// No continuity -> no release -> no unwrap -> no LK -> no ratchet (fail-closed).
    @discardableResult
    public func advanceEpoch(wrappedEpochKey: Data, wrappedLK: Data, drandRound: Data,
                             liveBiometric: Data, pole: PoLEState) throws -> SessionKey {
        guard let secret = presence.release(liveBiometric: liveBiometric, pole: pole) else {
            throw PresenceRequired.noLivePresence
        }
        let epochKey: Data
        do { epochKey = try Presence.unwrapEpochKey(wrappedEpochKey, presenceSecret: secret, drandRound: drandRound) }
        catch { throw PresenceRequired.epochUnwrapFailed }
        let lk: Data
        do { lk = try Presence.unlockLK(wrappedLK, epochKey: epochKey, drandRound: drandRound) }
        catch { throw PresenceRequired.lkUnlockFailed }

        // PoLE_value: a physiologically-TIMED QRNG value (clean QRNG; timing only
        // scheduled the firing).
        let poleValue = PoLE.firePoLEValue(physioFireMoment: pole.pLive)
        let sk = Derivation.sessionKeyDecoupled(lk: lk, epochKey: epochKey, poleValue: poleValue,
                                                prevKey: prevSessionBytes, contextSeparator: Params.contextTunnel,
                                                drandRound: drandRound)
        prevSessionBytes = try sk.key
        session = sk
        return sk
    }

    /// Convenience for the enrolled user being present. Server side: the epoch key
    /// WRAPS the LK, and presence WRAPS the epoch key. Device side: advance under
    /// the device's own enrolled biometric + an operating PoLE. `lk`/`epochKey` are
    /// the clean QRNG values the server produced (NOT drand).
    @discardableResult
    public func advanceEpochPresent(lk: Data, epochKey: Data, drandRound: Data,
                                    pole: PoLEState? = nil) throws -> SessionKey {
        let p = pole ?? PoLEState(pLive: 1.0, stateDigest: Primitives.H(Data("atlas/present".utf8), drandRound),
                                  drandRound: drandRound, operate: true)
        let wrappedLK = try Presence.wrapLK(lk, epochKey: epochKey, drandRound: drandRound)
        let wrappedEpochKey = try wrapEpochKey(epochKey, drandRound: drandRound)
        return try advanceEpoch(wrappedEpochKey: wrappedEpochKey, wrappedLK: wrappedLK, drandRound: drandRound,
                                liveBiometric: enrolledBiometric, pole: p)
    }

    public func currentSession() throws -> SessionKey {
        guard let s = session else { throw KeyError.destroyed }
        return s
    }

    private func wipeSession() {
        // Containment (§2.2): destroy ALL session-derived material in RAM — the
        // live SessionKey, the ratchet's prev-key copy, and the continuity-chain key.
        session?.destroy()
        prevSessionBytes = Data(repeating: 0, count: 32)
        continuityKey = nil
    }

    // -- independent continuity ratchet (§5.3) — local 10s ± biological jitter --

    /// Time the next inter-ratchet interval from the enrolled ring's live
    /// BIOLOGICAL signal (10s ± biological jitter, §16). Schedule only — the signal
    /// never becomes key material.
    @discardableResult
    public func nextRatchetInterval(bioSignal: Data) throws -> Double {
        try ratchetClock.nextInterval(bioSignal: bioSignal)
    }

    /// One continuity ratchet step on the LOCAL clock (§5.3).
    ///
    /// NO CACHE (§18): `beacon` is the CURRENT beacon consumed FRESH at this tick.
    /// A missing/stale beacon makes the device INERT (fail-closed) — it wipes and
    /// does NOT fall back to any prior value. Attests FIRST: a non-operating PoLE
    /// is a liveness break -> containment wipes, no new key. On operate, a
    /// forward-secret step folds fresh QRNG entropy + the FRESH beacon. NO timing
    /// is folded into the value.
    @discardableResult
    public func continuityTick(_ pole: PoLEState, drandRound: Data, beacon: Data,
                               challenge: Data = Data()) throws -> ContinuityTick {
        let intervalS = ratchetClock.lastInterval ?? 0.0
        // fail-closed on an absent/stale beacon: never fold a stale value -> inert.
        if beacon.isEmpty {
            wipeSession()
            return ContinuityTick(intervalS: intervalS, continuityKey: Data(), attestation: nil, operate: false)
        }
        // Thread the freshness challenge into the enclave attestation (mirrors
        // device.py's attest(pole, challenge=challenge)); attest() length-prefixes
        // it into the signed message.
        guard let att = attestation.attest(pole, challenge: challenge) else {
            // liveness break / suspended: no key advance (containment fired).
            return ContinuityTick(intervalS: intervalS, continuityKey: Data(), attestation: nil, operate: false)
        }
        if continuityKey == nil {
            continuityKey = try currentSession().key      // seed from live session
        }
        let entropyT = Primitives.randomBytes(32)         // clean QRNG; no timing in value
        continuityKey = Derivation.ratchet(continuityKey!, entropyT: entropyT, beaconT: beacon, drandRound: drandRound)
        return ContinuityTick(intervalS: intervalS, continuityKey: continuityKey!, attestation: att, operate: true)
    }

    // -- recognition + tunnel (§4) — unchanged X25519 handshake --------------

    public func recognitionContribution(beacon: Data) throws
        -> (priv: Curve25519.KeyAgreement.PrivateKey, pub: RecognitionContribution) {
        Recognition.contribution(sessionKey: try currentSession().key, beacon: beacon)
    }

    @discardableResult
    public func establishTunnel(myPriv: Curve25519.KeyAgreement.PrivateKey, myPub: Data,
                                their: RecognitionContribution, beacon: Data) -> Data {
        let rec = Recognition.value(myPriv: myPriv, theirPub: their.publicKey, myPub: myPub, beacon: beacon)
        tunnelKey = Recognition.evolveTunnelKey(tunnelKey, recognition: rec)
        return tunnelKey
    }

    /// Forward-secret message ratchet (§2.2): mixes FRESH SECRET entropy each
    /// step. Returns (nextKey, entropyT). Without entropyT a captured earlier key
    /// cannot derive the next key (§10.1).
    public func messageRatchetStep(_ prev: Data, beaconT: Data, drandRound: Data) -> (next: Data, entropy: Data) {
        let entropy = Primitives.randomBytes(32)
        return (Derivation.ratchet(prev, entropyT: entropy, beaconT: beaconT, drandRound: drandRound), entropy)
    }
}
