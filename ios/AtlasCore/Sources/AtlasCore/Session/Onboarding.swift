import Foundation

/// Onboarding: the single identification phase + the phase gate (§2.1). Mirrors
/// `backend/atlas/session/onboarding.py`.
///
/// Two phases, in order:
///   * Phase 1 — Identification. Establishes ALL of {TSK, System-ID, device
///     enrollment, pseudonyms} together in ONE phase (FIX #2). Device enrollment
///     binds each device's PUBLIC auth half to the BLIND System-ID, not the
///     person, for challenge-response authentication (FIX #6).
///   * Phase 2 — Liveness / PoLE streaming. HARD-GATED behind completed
///     identification (FIX #1): `beginLivenessStreaming` throws if identification
///     is not complete, and only for a device enrolled in it.

/// PoLE/liveness streaming attempted before identification completed.
public enum PhaseError: Error, Equatable {
    /// identification must complete before PoLE/liveness streaming
    case identificationIncomplete
    /// device was not enrolled in the identification phase
    case deviceNotEnrolled
}

/// Server side of device enrollment + challenge-response (§2.4 / FIX #6).
///
/// Holds each device's PUBLIC auth half (from enrollment), bound to the BLIND
/// System-ID (never the person). Issues fresh challenges and verifies responses;
/// never sees a private half. The System-ID binding is the firewall: the device
/// is authenticated to a verified identity while unlinked to the human.
public final class EnrollmentAuthority {
    private var enrolled: [String: (authPublic: HybridSign.PublicKey, systemID: Data)] = [:]

    public init() {}

    public func enroll(deviceName: String, authPublic: HybridSign.PublicKey, systemIDHandle: Data) {
        enrolled[deviceName] = (authPublic, systemIDHandle)
    }

    public func isEnrolled(_ deviceName: String) -> Bool {
        enrolled[deviceName] != nil
    }

    public func systemIdOf(_ deviceName: String) -> Data {
        enrolled[deviceName]!.systemID
    }

    /// A fresh, unpredictable challenge for challenge-response.
    public func issueChallenge() -> Data {
        Primitives.randomBytes(32)
    }

    /// Verify the device signed our challenge with the enrolled public half.
    public func verifyResponse(deviceName: String, challenge: Data, response: Data) -> Bool {
        guard let entry = enrolled[deviceName] else { return false }
        return HybridSign.verify(entry.authPublic, challenge, response)
    }
}

/// The identified user produced by Phase 1 (mirrors `IdentifiedUser`). Reference
/// type so the phase gate can record which devices began streaming.
public final class IdentifiedUser {
    public let tree: IdentityTree
    public let authority: EnrollmentAuthority
    public let devices: [Device]
    public let pseudonyms: [String: Child]
    var livenessStarted: Set<String> = []

    init(tree: IdentityTree, authority: EnrollmentAuthority, devices: [Device],
         pseudonyms: [String: Child]) {
        self.tree = tree; self.authority = authority
        self.devices = devices; self.pseudonyms = pseudonyms
    }
}

/// The identification -> liveness phase machine with a hard gate.
public final class Onboarding {
    public private(set) var identified = false
    public private(set) var user: IdentifiedUser?

    public init() {}

    /// Phase 1 — establish TSK + System-ID + device enrollment + pseudonyms
    /// TOGETHER (FIX #2). Returns the identified user; only now may liveness begin.
    @discardableResult
    public func identify(tskSeed: Data, deviceNames: [String],
                         pseudonyms: [(label: String, tier: PseudonymTier)],
                         sphincs: SphincsProvider) throws -> IdentifiedUser {
        let tree = try IdentityTree.build(tskSeed: tskSeed, sphincs: sphincs)
        let authority = EnrollmentAuthority()
        var devices: [Device] = []
        for name in deviceNames {
            let dev = Device(name: name, identity: tree, bootstrapTunnelKey: Primitives.randomBytes(32))
            // device enrollment is PART of identification: bind the device's public
            // auth half to the BLIND System-ID (not the person).
            authority.enroll(deviceName: name, authPublic: dev.devicePublic(), systemIDHandle: tree.systemIDHandle())
            devices.append(dev)
        }
        var pmap: [String: Child] = [:]
        for (label, tier) in pseudonyms {
            pmap[label] = try tree.pseudonym(label, tier: tier)
        }
        let u = IdentifiedUser(tree: tree, authority: authority, devices: devices, pseudonyms: pmap)
        self.user = u
        self.identified = true
        return u
    }

    /// Phase gate (FIX #1): HARD guard. No PoLE/liveness streaming until
    /// identification is complete, and only for a device enrolled in it.
    @discardableResult
    public func beginLivenessStreaming(_ device: Device) throws -> Device {
        guard identified, let user = user else { throw PhaseError.identificationIncomplete }
        guard user.devices.contains(where: { $0.name == device.name }) else {
            throw PhaseError.deviceNotEnrolled
        }
        user.livenessStarted.insert(device.name)
        return device
    }
}
