import Foundation
import CryptoKit

/// The device-attestation contract (TRUST_LAYER.md #11). Mirrors
/// `backend/atlas/attestation/device.py` — the platform-neutral rules for "any device that
/// proves itself worthy". Capabilities are DERIVED from proof (never asserted); the assurance
/// tier composes fail-closed. The iOS `Wearable` seam is the BLE *driver* that feeds this
/// contract; this is the semantics every platform must reproduce byte-for-byte.
public enum TrustedDevice {

    /// What a device can prove. Raw values are part of the contract (must match Python).
    public struct Capability: OptionSet, Sendable {
        public let rawValue: Int
        public init(rawValue: Int) { self.rawValue = rawValue }
        public static let liveness      = Capability(rawValue: 1 << 0)  // live presence (pulse)
        public static let onBodyMotion  = Capability(rawValue: 1 << 1)  // worn-vs-not
        public static let highRateIMU   = Capability(rawValue: 1 << 2)  // same-hand tap bind
        public static let secureElement = Capability(rawValue: 1 << 3)  // hardware key store
        public static let sameBody      = Capability(rawValue: 1 << 4)  // cross-device coherence
        public static let identity      = Capability(rawValue: 1 << 5)  // bound identity
    }

    /// Assurance tiers — compose fail-closed & monotonically (a missing lower rung caps the tier).
    public enum AssuranceTier: Int, Comparable {
        case none = 0, presence = 1, bound = 2, attested = 3, identified = 4
        public static func < (a: AssuranceTier, b: AssuranceTier) -> Bool { a.rawValue < b.rawValue }
    }

    static func presence(_ c: Capability) -> Bool { c.contains(.liveness) }
    static func bound(_ c: Capability) -> Bool {
        presence(c) && (c.contains(.highRateIMU) || c.contains(.sameBody))
    }
    static func attested(_ c: Capability) -> Bool { bound(c) && c.contains(.secureElement) }
    static func identified(_ c: Capability) -> Bool { attested(c) && c.contains(.identity) }

    /// The highest tier whose requirements the proven capabilities meet. Fail-closed: the
    /// monotonic predicates mean an out-of-order capability never lifts the tier.
    public static func assuranceTier(_ capabilities: Capability) -> AssuranceTier {
        var tier: AssuranceTier = .none
        if presence(capabilities) { tier = .presence }
        if bound(capabilities) { tier = .bound }
        if attested(capabilities) { tier = .attested }
        if identified(capabilities) { tier = .identified }
        return tier
    }

    /// A device's claim to a capability, backed by evidence. No evidence -> not proven.
    public struct CapabilityClaim {
        public let capability: Capability
        public let evidence: Data
        public init(capability: Capability, evidence: Data) {
            self.capability = capability; self.evidence = evidence
        }
    }

    static let claimLabel = Data("atlas/device-attest-claim".utf8)

    /// Length-prefix framing so a variable-length field cannot be re-split into the next one.
    static func lp(_ d: Data) -> Data {
        var n = UInt32(d.count).bigEndian
        return withUnsafeBytes(of: &n) { Data($0) } + d
    }

    /// The exact bytes an attestor signs to vouch for a capability, bound to device + challenge.
    /// deviceID and challenge are length-prefixed so the boundaries with the fixed-width
    /// capability are unambiguous (mirrors backend `claim_message`).
    public static func claimMessage(deviceID: Data, capability: Capability, challenge: Data) -> Data {
        var caps = UInt32(capability.rawValue).bigEndian
        return Primitives.H(claimLabel, lp(deviceID), withUnsafeBytes(of: &caps) { Data($0) }, lp(challenge))
    }

    /// Produce the evidence for a capability (the honest attestor / test side).
    public static func signCapability(_ sk: Curve25519.Signing.PrivateKey, deviceID: Data,
                                      capability: Capability, challenge: Data) -> Data {
        (try? sk.signature(for: claimMessage(deviceID: deviceID, capability: capability, challenge: challenge))) ?? Data()
    }

    static func verifyClaim(attestorPublic: Data, deviceID: Data, capability: Capability,
                            challenge: Data, signature: Data) -> Bool {
        guard let pk = try? Curve25519.Signing.PublicKey(rawRepresentation: attestorPublic) else { return false }
        return pk.isValidSignature(signature, for: claimMessage(deviceID: deviceID, capability: capability, challenge: challenge))
    }

    /// The proven capability set: the union of capabilities whose attestation SIGNATURE verifies.
    /// Fail-closed — an absent, malformed, or forged signature admits nothing.
    public static func deriveCapabilities(_ claims: [CapabilityClaim], attestorPublic: Data,
                                          deviceID: Data, challenge: Data) -> Capability {
        var proven: Capability = []
        for claim in claims where !claim.evidence.isEmpty
            && verifyClaim(attestorPublic: attestorPublic, deviceID: deviceID,
                           capability: claim.capability, challenge: challenge, signature: claim.evidence) {
            proven.insert(claim.capability)
        }
        return proven
    }

    static let digestLabel = Data("atlas/device-attestation".utf8)

    /// A byte-exact commitment to a device's attested state.
    public static func attestationDigest(deviceID: Data, capabilities: Capability,
                                         tier: AssuranceTier) -> Data {
        var caps = UInt32(capabilities.rawValue).bigEndian
        let tierByte = Data([UInt8(tier.rawValue)])
        return Primitives.H(digestLabel, deviceID, withUnsafeBytes(of: &caps) { Data($0) }, tierByte)
    }

    /// A device's attested state: who it is + what it PROVED. Tier and digest are derived.
    public struct Attestation {
        public let deviceID: Data
        public let capabilities: Capability
        public init(deviceID: Data, capabilities: Capability) {
            self.deviceID = deviceID; self.capabilities = capabilities
        }
        public static func fromClaims(deviceID: Data, claims: [CapabilityClaim],
                                      attestorPublic: Data, challenge: Data) -> Attestation {
            Attestation(deviceID: deviceID, capabilities: deriveCapabilities(
                claims, attestorPublic: attestorPublic, deviceID: deviceID, challenge: challenge))
        }
        public var tier: AssuranceTier { assuranceTier(capabilities) }
        public func meets(_ required: AssuranceTier) -> Bool { tier >= required }
        public func digest() -> Data { attestationDigest(deviceID: deviceID, capabilities: capabilities, tier: tier) }
    }
}
