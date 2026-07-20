import Foundation

/// The swappable-wearable seam. The app depends on THIS, not on any one ring — so a Colmi
/// R10 (pulse only), a purpose-built nRF5340 ring (pulse + high-rate IMU + a secure element),
/// an Apple Watch, or a future device all plug in behind one interface. Features light up
/// from `capabilities`, so the app DEGRADES GRACEFULLY on a limited wearable and a
/// firmware/hardware upgrade UNLOCKS more with no app change.
///
/// This is the same discipline as `SignalSource` (ambient vs ring) — one seam, many sources.
public struct WearableCapabilities: OptionSet, Sendable {
    public let rawValue: Int
    public init(rawValue: Int) { self.rawValue = rawValue }

    /// A live pulse (PPG) — the liveness/presence signal. The one universal capability.
    public static let pulse         = WearableCapabilities(rawValue: 1 << 0)
    /// On-body motion (low-rate accelerometer) — removal / worn-vs-not.
    public static let onBodyMotion  = WearableCapabilities(rawValue: 1 << 1)
    /// High-rate IMU (~50 Hz+) — sharp finger taps + the accelerometer ballistocardiogram.
    public static let highRateIMU   = WearableCapabilities(rawValue: 1 << 2)
    /// A secure element / on-device key store — holds the bind secret and presents
    /// challenge-response RESUMPTION CODES across a disconnect (the R10 cannot; an nRF5340 can).
    public static let secureElement = WearableCapabilities(rawValue: 1 << 3)
}

/// Any wearable the app can drive. Presence-critical members are required; capability-gated
/// members return an empty/nil default when the wearable lacks the capability, so callers
/// branch on `capabilities`, never on a concrete device type. `@MainActor` because every
/// wearable is a main-actor BLE/UI object (like `RingProbe`).
@MainActor
public protocol Wearable: AnyObject {
    var deviceName: String { get }
    var isConnected: Bool { get }
    var capabilities: WearableCapabilities { get }

    /// A live pulse right now (fail-closed when absent). `.pulse`.
    var pulsePresent: Bool { get }
    /// The presence window feeding the liveness `SignalSource`. `.pulse`.
    func presenceWindow() -> Data

    /// Tap onset times over the last `windowS` seconds (for the handshake bind). `.highRateIMU`
    /// — returns [] when unsupported, so the caller falls back to the degraded challenge.
    func tapTimes(windowS: Double) -> [Double]

    /// A one-time resumption code for reconnect #counter, from the wearable's secure element.
    /// `.secureElement` — returns nil when unsupported, so the caller uses pulse-based resume.
    func resumptionCode(counter: Int) -> Data?
}

public extension Wearable {
    var supportsSameHandBind: Bool { capabilities.contains(.highRateIMU) }
    var supportsResumptionCodes: Bool { capabilities.contains(.secureElement) }
    /// A short human summary of what this wearable can prove — shown honestly in the UI.
    var assuranceSummary: String {
        var parts: [String] = []
        if capabilities.contains(.pulse) { parts.append("live pulse") }
        if capabilities.contains(.highRateIMU) { parts.append("same-hand tap bind") }
        else if capabilities.contains(.onBodyMotion) { parts.append("on-body motion") }
        if capabilities.contains(.secureElement) { parts.append("resumption codes") }
        return parts.isEmpty ? "no capabilities" : parts.joined(separator: " · ")
    }
}
