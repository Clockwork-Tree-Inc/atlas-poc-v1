import Foundation

/// Sensitive space — a records-backed space at the HIGH-PROTECTION tier, unifying the two layers.
/// Parity with `backend/atlas/spaces/sensitive_space.py`. The SPACE POLICY (roles + quorum + audit)
/// decides WHO may act; the RECORDS layer decides WHEN/HOW the content opens (windows, retention,
/// break-glass, threshold reopen). Both must pass — role-gates WHO, records-gates WHEN.
public enum SensitiveSpaceNS {

    public enum SensitiveSpaceError: Error, Equatable { case missingRole }

    public struct SensitiveSpace {
        public let policy: SpaceGovernance.SpacePolicy
        public let record: Records.SealedRecord
        public let log: Records.AccessLog
        public init(policy: SpaceGovernance.SpacePolicy, record: Records.SealedRecord, log: Records.AccessLog) {
            self.policy = policy; self.record = record; self.log = log
        }
    }

    static func who(_ member: HybridSign.PublicKey) -> String {
        String(member.encode().map { String(format: "%02x", $0) }.joined().prefix(16))
    }

    static func require(_ space: SensitiveSpace, _ member: HybridSign.PublicKey, _ role: SpaceGovernance.Role) throws {
        guard space.policy.can(member, role) else { throw SensitiveSpaceError.missingRole }
    }

    /// A READER+ member opens the record; every open is logged (symmetric trail).
    public static func openOwn(_ space: SensitiveSpace, member: HybridSign.PublicKey,
                               contentKey: Data, nowRound: Int, aad: Data = Data()) throws -> Data {
        try require(space, member, .reader)
        return try Records.patientOpenOwn(space.record, contentKey: contentKey, log: space.log,
                                          nowRound: nowRound, patient: who(member), aad: aad)
    }

    /// A CONTRIBUTOR+ member opens within the episode — role-gated AND records-gated.
    public static func openEpisode(_ space: SensitiveSpace, member: HybridSign.PublicKey,
                                   grant: Records.EpisodeGrant, episodeKey: Data, nowRound: Int,
                                   presenceLive: Bool, aad: Data = Data()) throws -> Data {
        try require(space, member, .contributor)
        return try Records.clinicianOpenEpisode(grant, record: space.record, episodeKey: episodeKey,
                                                nowRound: nowRound, presenceLive: presenceLive,
                                                log: space.log, clinician: who(member), aad: aad)
    }

    /// Only a BREAK_GLASS-role holder may emergency-open; the open is loud (logged + notified).
    public static func breakGlass(_ space: SensitiveSpace, member: HybridSign.PublicKey,
                                  breakGlassKey: Data, wrappedContentKey: Data, nowRound: Int) throws -> Data {
        try require(space, member, .breakGlass)
        return try Records.breakGlassOpen(space.record, breakGlassKey: breakGlassKey,
                                          wrappedContentKey: wrappedContentKey, nowRound: nowRound,
                                          log: space.log, clinician: who(member))
    }

    /// Reopen the retained record — records threshold (doctor AND body share, within retention) is the
    /// arithmetic gate; the governor quorum is what authorized handing out the body-share.
    public static func reopenDispute(_ space: SensitiveSpace, doctorShare: Shamir.Share, bodyShare: Shamir.Share,
                                     nowRound: Int, retentionEnd: Int, aad: Data = Data()) throws -> Data {
        try Records.reopenRetained(space.record, doctorShare: doctorShare, bodyShare: bodyShare,
                                   nowRound: nowRound, retentionEnd: retentionEnd, log: space.log, aad: aad)
    }
}
