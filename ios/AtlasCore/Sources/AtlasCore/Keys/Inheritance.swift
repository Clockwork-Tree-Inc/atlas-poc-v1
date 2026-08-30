import Foundation

/// Inheritance gate — release an heir's custody share ONLY on a death-trigger AND only if the owner
/// fails to veto by proving they're alive. Byte-for-byte parity with `backend/atlas/keys/inheritance.py`
/// (Python is reference-of-record).
///
///     release  ==  a death-trigger fired  AND  the owner did not prove liveness within the window
///
/// TRIGGER (executor signs at a drand round → opens a challenge window) · VETO (owner signs a
/// liveness proof bound to a POST-trigger beacon signature → aborts the trigger; unforgeable
/// freshness so it can't be pre-signed) · RELEASE (only if the window elapses with no veto).
public enum Inheritance {

    static let triggerLabel = Data("atlas/inherit/trigger/v1".utf8)
    static let vetoLabel = Data("atlas/inherit/veto/v1".utf8)

    public enum InheritanceError: Error, Equatable {
        case alreadyReleased
        case notTriggered        // a veto/release with no active trigger
        case windowElapsed       // veto before the trigger or after the window
        case badAuthority        // a trigger/veto signature did not verify
        case releaseNotMet
        case badPolicy
    }

    static func be8(_ n: Int) -> Data { var v = UInt64(n).bigEndian; return withUnsafeBytes(of: &v) { Data($0) } }

    public static func triggerMessage(gateID: Data, atRound: Int) -> Data {
        Primitives.H(triggerLabel, gateID, be8(atRound))
    }

    /// Binds the owner's liveness proof to a specific drand round's SIGNATURE — unpredictable until
    /// that round is published, so a veto cannot be pre-signed ahead of the trigger.
    public static func vetoMessage(gateID: Data, atRound: Int, beaconSig: Data) -> Data {
        Primitives.H(vetoLabel, gateID, be8(atRound), beaconSig)
    }

    /// Inheritance is a LEGAL process: the attorney/representative triggers, the OWNER vetoes by
    /// proving liveness, a time-lock gives the challenge window, and the appointed heir's share
    /// releases if unchallenged. Guardians are NOT involved (they are for the LIVING owner's own
    /// recovery); disputes defer to a COURT, supported by this beacon-clocked, tamper-evident record.
    public struct InheritancePolicy {
        public let gateID: Data
        public let ownerPub: HybridSign.PublicKey     // who can VETO (prove alive)
        public let triggerPub: HybridSign.PublicKey   // who can TRIGGER (attorney / representative)
        public let vetoWindowRounds: Int              // the time-lock / challenge window

        public init(gateID: Data, ownerPub: HybridSign.PublicKey, triggerPub: HybridSign.PublicKey,
                    vetoWindowRounds: Int) throws {
            guard vetoWindowRounds > 0 else { throw InheritanceError.badPolicy }
            guard gateID.count >= 16 else { throw InheritanceError.badPolicy }
            self.gateID = gateID; self.ownerPub = ownerPub; self.triggerPub = triggerPub
            self.vetoWindowRounds = vetoWindowRounds
        }
    }

    public final class GateState {
        public var triggeredAt: Int?     // drand round the active trigger fired (nil = armed)
        public var vetoCount: Int
        public var released: Bool
        public init(triggeredAt: Int? = nil, vetoCount: Int = 0, released: Bool = false) {
            self.triggeredAt = triggeredAt; self.vetoCount = vetoCount; self.released = released
        }
    }

    /// Attorney/representative fires a death-trigger at `atRound`, (re)opening the challenge window.
    @discardableResult
    public static func applyTrigger(_ policy: InheritancePolicy, _ state: GateState,
                                    atRound: Int, signature: Data) throws -> GateState {
        if state.released { throw InheritanceError.alreadyReleased }
        guard HybridSign.verify(policy.triggerPub, triggerMessage(gateID: policy.gateID, atRound: atRound), signature)
        else { throw InheritanceError.badAuthority }
        state.triggeredAt = atRound
        return state
    }

    /// Owner proves liveness within the window → ABORT this trigger.
    @discardableResult
    public static func applyVeto(_ policy: InheritancePolicy, _ state: GateState,
                                 atRound: Int, beaconSig: Data, signature: Data) throws -> GateState {
        guard let triggeredAt = state.triggeredAt else { throw InheritanceError.notTriggered }
        if atRound < triggeredAt { throw InheritanceError.windowElapsed }
        if atRound > triggeredAt + policy.vetoWindowRounds { throw InheritanceError.windowElapsed }
        guard HybridSign.verify(policy.ownerPub, vetoMessage(gateID: policy.gateID, atRound: atRound, beaconSig: beaconSig), signature)
        else { throw InheritanceError.badAuthority }
        state.triggeredAt = nil          // the owner is alive → abort; a later trigger can re-open
        state.vetoCount += 1
        return state
    }

    public static func canRelease(_ policy: InheritancePolicy, _ state: GateState, nowRound: Int) -> Bool {
        guard !state.released, let triggeredAt = state.triggeredAt else { return false }
        return nowRound > triggeredAt + policy.vetoWindowRounds
    }

    @discardableResult
    public static func markReleased(_ policy: InheritancePolicy, _ state: GateState, nowRound: Int) throws -> GateState {
        guard canRelease(policy, state, nowRound: nowRound) else { throw InheritanceError.releaseNotMet }
        state.released = true
        return state
    }

    /// Human-facing state: "released" | "releasable" | "challenge" | "armed".
    public static func status(_ policy: InheritancePolicy, _ state: GateState, nowRound: Int) -> String {
        if state.released { return "released" }
        guard let triggeredAt = state.triggeredAt else { return "armed" }
        return nowRound > triggeredAt + policy.vetoWindowRounds ? "releasable" : "challenge"
    }
}
