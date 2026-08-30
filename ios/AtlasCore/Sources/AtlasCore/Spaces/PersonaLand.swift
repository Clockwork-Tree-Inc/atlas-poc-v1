import Foundation

/// A persona's own "LAND": a self-owned space it can HOST arbitrary digital content into
/// (files, media, app bundles, game state, pages — all opaque bytes), with provenance
/// (commitment), access control (owner-gated), and persistence (PRESENT→PUBLIC). This is the
/// "host anything digital" primitive — `SpaceDescriptor.vaultID` links the land to the
/// persona's vault ("your vault is your land; a shop/game/forum is a sub-space of it").
///
/// A Swift-side COMPOSITION of already-parity'd primitives (FSSign authority + Authority grants
/// + SpaceStore + GlobalAnchor) — not a Python port, so it's tested for behaviour, not parity.
/// The content BYTES are sealed in the persona's vault (app layer); this holds the
/// commitment + access + persistence.
extension Spaces {
    public struct PersonaLand {
        public let space: SpaceDescriptor
        public let store: SpaceStore
        public let authorHandle: Data           // the land owner's opaque handle
        fileprivate let ownerGrant: Authority.Grant

        /// Host a digital artifact (arbitrary bytes) into this land — owner-gated, committed,
        /// persisted per `persistence` (defaults to the space's mode). Returns the hosted item;
        /// its `contentHash` is the provenance commitment to seal-and-serve the bytes under.
        @discardableResult
        public func host(_ content: Data, now: UInt64,
                         persistence: PersistenceMode? = nil, parent: Data? = nil) throws -> SpaceItem {
            try store.post(authorChain: [ownerGrant], author: authorHandle, content: content,
                           now: now, persistence: persistence, parent: parent)
        }

        /// Everything currently hosted (FADING items past expiry pruned).
        public func hosted(now: UInt64) -> [SpaceItem] { store.live(now: now) }
    }

    /// Create a persona's hosting land: a SELF-owned space (only the persona hosts), linked to the
    /// persona's vault via `vaultID`. Derives the land's forward-secure owner root + host key from
    /// the persona seed, and mints the owner grant so the persona can post to its own land.
    public static func createLand(personaSeed: Data, spaceID: Data, vaultID: Data,
                                  persistence: PersistenceMode = .privateMode,
                                  globalAnchor: GlobalAnchor.Log? = nil) throws -> PersonaLand {
        let fsSeed = Primitives.hkdf(ikm: personaSeed, info: Data("atlas/land/fs".utf8), length: 32)
        let hostSeed = Primitives.hkdf(ikm: personaSeed, info: Data("atlas/land/host".utf8), length: 32)
        let (root, signer) = try FSSign.keygen(seed: fsSeed, height: 4)
        let hostKey = try HybridSign.keypair(fromSeed: hostSeed)
        // SELF space: only the owner posts; pseudonymous accountability; lives in the persona vault.
        let space = makeSpace(spaceID, kind: .sef, ownerRoot: root, persistence: persistence,
                              access: .selfOnly, identity: .pseudonymous, vaultID: vaultID)
        let ownerGrant = try Authority.issueFS(signer, grantee: hostKey.publicKey, resource: spaceID,
                                               rights: Authority.RightSet(Role.owner.rawValue))
        let store = SpaceStore(space: space, globalAnchor: globalAnchor)
        return PersonaLand(space: space, store: store,
                           authorHandle: handleOf(hostKey.publicKey.encode()), ownerGrant: ownerGrant)
    }

    /// App-facing convenience: create a persona's land WITHOUT the caller needing the persona's
    /// (module-internal) seed. The space + vault ids come from the persona's PUBLIC opaque feature
    /// handles (per-persona, unlinkable across personas); the secret land seed is derived from the
    /// persona seed inside the module.
    public static func createLand(for profile: Profile,
                                  persistence: PersistenceMode = .privateMode,
                                  globalAnchor: GlobalAnchor.Log? = nil) throws -> PersonaLand {
        try createLand(personaSeed: profile.seed,
                       spaceID: try profile.feature("land").handle,
                       vaultID: try profile.feature("vault").handle,
                       persistence: persistence, globalAnchor: globalAnchor)
    }
}
