import Foundation

/// Protocol parameters and the resolved §3.2 / §22.1 build-gating decisions.
///
/// Mirrors `backend/atlas/params.py`. Single source of truth for the PoC
/// defaults the user ratified.
public enum Params {
    // §3.2 #1 — CORRECTED by the Locked Model §2.3 one-principle: timing TIMES
    // *when* the QRNG fires but is NEVER folded into any value. The fired value
    // is clean QRNG; the timing digest no longer enters the value bytes.
    public static let commitInterArrivalTiming = false
    // §3.2 #2 — tunnel is SYMMETRIC (jointly rooted); neither device leads.
    public static let tunnelRooting = "symmetric"
    // §3.2 #3 — server returns timed randomness only; device composes locally.
    public static let serverReturnsTimedRandomnessOnly = true
    // §3.2 #4 — recognition-window width epsilon (seconds).
    public static let recognitionWindowEpsilon: TimeInterval = 2.0
    // §3.2 #5 — epoch length floor/cap (the replay window), seconds. This is the
    // BEACON clock, NOT the device ratchet clock.
    public static let epochLengthFloor: TimeInterval = 3.0
    public static let epochLengthCap: TimeInterval = 30.0

    // §5.3 — device continuity-ratchet clock, INDEPENDENT of the two beacon
    // clocks. Three decoupled clocks, each consuming its beacon FRESH (NO caching,
    // §18); every clock = base period + BIOLOGICAL jitter (§16) that only TIMES
    // the firing and never enters a value:
    //   * device ratchet 10s +- 2   (jitter = enrolled ring signal)   <- on phone
    //   * LK (LKG)       30s +- 5   (jitter = aggregate PoLE-arrival timing, server)
    //   * epoch key      ~per minute (jitter = aggregate LK cadence, server)
    // A missing/stale beacon at a tick makes the device INERT (fail-closed), never
    // a fall back to a cached value.
    // Nominal device ratchet period (the base-period rail).
    public static let ratchetNominalS: TimeInterval = 10.0
    // Half-width of the biological jitter band: interval in [nominal +- jitter].
    // Must stay < nominal so intervals are always positive. The offset within the
    // band is timed by the enrolled ring's live signal (NOT an RNG).
    public static let ratchetJitterS: TimeInterval = 2.0

    // §5.2 — operate only if P(L|S) >= piStar.
    public static let piStar = 0.95
    // §6 calibration-window Beta(a0,b0) prior on P(L).
    public static let livenessPriorA0 = 2.0
    public static let livenessPriorB0 = 1.0

    // §2.3 context separators (HKDF info labels).
    public static let contextStorage = Data("atlas/storage".utf8)
    public static let contextRecognition = Data("atlas/recognition".utf8)
    public static let contextTunnel = Data("atlas/tunnel".utf8)

    // Domain-separation labels for the hybrid primitives.
    public static let labelXWing = Data("atlas/x-wing/v1".utf8)
    public static let labelRatchet = Data("atlas/ratchet/v1".utf8)
    public static let labelSession = Data("atlas/session/v1".utf8)
}
