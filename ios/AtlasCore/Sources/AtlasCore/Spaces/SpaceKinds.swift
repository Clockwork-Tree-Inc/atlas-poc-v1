import Foundation

/// Space kinds, persistence modes, roles, and authority-based invitation — mirrors
/// `backend/atlas/spaces/kinds.py`. One substrate, many shapes: every named Space kind is a
/// constructor over one descriptor; membership rides the (forward-secure) authority engine.
/// Extends the base `Spaces` namespace (Space.swift — the vault primitive).
extension Spaces {

    public enum SpaceKind: String {
        case sef = "self"          // 'self' is reserved in Swift; wire value stays "self"
        case direct, family, friends, movement, host, org, commons
    }

    /// LOCKED, orthogonal. rawValue = escalation rank (least → most durable/witnessed).
    public enum PersistenceMode: Int {
        case present = 0   // live only, then gone — no stored copy
        case fading = 1    // user-set duration, then deleted
        case privateMode = 2   // permanent; ledgered between the parties
        case publicMode = 3    // permanent; global-anchored, provable to anyone
    }

    public static func persistenceBackend(_ m: PersistenceMode) -> String {
        switch m {
        case .present: return "blind-relay (no retention)"
        case .fading: return "relay / vault + TTL"
        case .privateMode: return "IndividualLedger (between the parties)"
        case .publicMode: return "GlobalAnchor (provable to anyone)"
        }
    }

    /// Space role ladder — reused as the authority RightSet level. Higher = more.
    public enum Role: Int {
        case none = 0, guest = 1, member = 2, moderator = 3, admin = 4, owner = 5
    }

    /// LOCKED — who may enter/post (the concentric rings), orthogonal to kind & persistence.
    /// SELF = owner only; INVITE = closed group (allow-list); MEMBER = admitted once then post freely;
    /// OPEN = any verified human, block-list (ban) moderation. Mirrors `Access` in kinds.py.
    public enum Access: Int {
        case selfOnly = 0   // 'self' reserved in Swift; wire value stays 0
        case invite = 1
        case member = 2
        case open = 3
    }

    static func defaultMode(_ k: SpaceKind) -> PersistenceMode {
        switch k {
        case .movement, .commons: return .publicMode
        default: return .privateMode
        }
    }

    static func defaultAccess(_ k: SpaceKind) -> Access {
        switch k {
        case .sef: return .selfOnly
        case .direct, .family, .friends: return .invite
        case .movement, .host, .org: return .member
        case .commons: return .open
        }
    }

    /// LOCKED — the accountability a space demands (orthogonal to kind/access/persistence). Mirrors
    /// `IdentityTier` in kinds.py; also the anonymity axis for polls. Real-ID never exposed even at top.
    public enum IdentityTier: Int {
        case anonymous = 0        // no persistent identity; ephemeral, unlinkable
        case pseudonymous = 1     // a persistent pseudonym (no personhood check)
        case verifiedPerson = 2   // personhood-backed pseudonym: one per human, accountable, real-ID hidden
    }

    static func defaultIdentity(_ k: SpaceKind) -> IdentityTier {
        // pseudonymous everywhere; the public square is verified-person (sybil-resistant).
        k == .commons ? .verifiedPerson : .pseudonymous
    }

    public struct SpaceDescriptor {
        public let spaceID: Data
        public let kind: SpaceKind
        public let ownerRoot: FSSign.FSPublicKey
        public let persistence: PersistenceMode
        public let access: Access
        public let identity: IdentityTier
        public let vaultID: Data?   // the vault (land) this space is built inside; nil = a top-level vault
    }

    public static func makeSpace(_ spaceID: Data, kind: SpaceKind, ownerRoot: FSSign.FSPublicKey,
                                 persistence: PersistenceMode? = nil, access: Access? = nil,
                                 identity: IdentityTier? = nil, vaultID: Data? = nil) -> SpaceDescriptor {
        SpaceDescriptor(spaceID: spaceID, kind: kind, ownerRoot: ownerRoot,
                        persistence: persistence ?? defaultMode(kind),
                        access: access ?? defaultAccess(kind),
                        identity: identity ?? defaultIdentity(kind), vaultID: vaultID)
    }

    // named-shape constructors (all one primitive)
    public static func selfSpace(_ id: Data, _ root: FSSign.FSPublicKey, _ p: PersistenceMode? = nil) -> SpaceDescriptor { makeSpace(id, kind: .sef, ownerRoot: root, persistence: p) }
    public static func direct(_ id: Data, _ root: FSSign.FSPublicKey, _ p: PersistenceMode? = nil) -> SpaceDescriptor { makeSpace(id, kind: .direct, ownerRoot: root, persistence: p) }
    public static func family(_ id: Data, _ root: FSSign.FSPublicKey, _ p: PersistenceMode? = nil) -> SpaceDescriptor { makeSpace(id, kind: .family, ownerRoot: root, persistence: p) }
    public static func friends(_ id: Data, _ root: FSSign.FSPublicKey, _ p: PersistenceMode? = nil) -> SpaceDescriptor { makeSpace(id, kind: .friends, ownerRoot: root, persistence: p) }
    public static func movement(_ id: Data, _ root: FSSign.FSPublicKey, _ p: PersistenceMode? = nil) -> SpaceDescriptor { makeSpace(id, kind: .movement, ownerRoot: root, persistence: p) }
    public static func host(_ id: Data, _ root: FSSign.FSPublicKey, _ p: PersistenceMode? = nil) -> SpaceDescriptor { makeSpace(id, kind: .host, ownerRoot: root, persistence: p) }
    public static func org(_ id: Data, _ root: FSSign.FSPublicKey, _ p: PersistenceMode? = nil) -> SpaceDescriptor { makeSpace(id, kind: .org, ownerRoot: root, persistence: p) }
    public static func commons(_ id: Data, _ root: FSSign.FSPublicKey, _ p: PersistenceMode? = nil) -> SpaceDescriptor { makeSpace(id, kind: .commons, ownerRoot: root, persistence: p) }

    // membership / invitation (rides the authority engine)
    public static func invite(_ space: SpaceDescriptor, ownerSigner: FSSign.FSSigner,
                              invitee: HybridSign.PublicKey, role: Role, delegable: Bool = false,
                              caveats: [Authority.Caveat] = []) throws -> Authority.Grant {
        try Authority.issueFS(ownerSigner, grantee: invitee, resource: space.spaceID,
                              rights: Authority.RightSet(role.rawValue), caveats: caveats,
                              delegableDepth: delegable ? 1 : 0)
    }

    public static func subInvite(_ parent: Authority.Grant, holder: HybridSign.Keypair,
                                 invitee: HybridSign.PublicKey, role: Role,
                                 addCaveats: [Authority.Caveat] = []) throws -> Authority.Grant {
        try Authority.delegate(parent, holder: holder, grantee: invitee,
                               rights: Authority.RightSet(role.rawValue), addCaveats: addCaveats)
    }

    /// The role a grant chain confers in this space (throws AuthorityError on any invalid chain).
    public static func memberRole(_ space: SpaceDescriptor, _ chain: [Authority.Grant], now: UInt64) throws -> Role {
        let rights = try Authority.verifyChain(chain, resource: space.spaceID, fsRoot: space.ownerRoot, now: now)
        return Role(rawValue: rights.level) ?? .none
    }

    /// Content-authorization gate: does the chain grant at least `min` role? (fail-closed).
    public static func hasRole(_ space: SpaceDescriptor, _ chain: [Authority.Grant], atLeast min: Role,
                               now: UInt64) -> Bool {
        let lvl = (try? memberRole(space, chain, now: now).rawValue) ?? -1
        return lvl >= min.rawValue
    }
}
