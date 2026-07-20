import Foundation

/// Group spaces (TRUST_LAYER.md #12). Mirrors `backend/atlas/spaces/space.py`. A space is a
/// k-of-n threshold root shared among members (who join under space-nyms, #13); the vault key is
/// derived from the reconstructed root, namespaced by `spaceID` (tenant isolation). Two thresholds:
/// ACCESS (open the vault) and GOVERNANCE (change membership). Reshare preserves the root, so
/// vault contents survive membership changes; the self-hosted store holds only ciphertext.
/// Composition over already-parity'd primitives (Shamir, SpacePseudonym, Primitives).
public enum Spaces {

    public enum SpaceError: Error, Equatable {
        case policy, duplicateMember, alreadyMember, notMember, targetStillPresent
        case governance, access, wrongSpace
    }

    public struct SpacePolicy: Equatable {
        public let accessThreshold: Int
        public let governanceThreshold: Int
        public init(accessThreshold: Int, governanceThreshold: Int) {
            self.accessThreshold = accessThreshold; self.governanceThreshold = governanceThreshold
        }
        func validate(n: Int) throws {
            for k in [accessThreshold, governanceThreshold] where !(1 < k && k <= n) {
                throw SpaceError.policy
            }
            // governance < access would reshare the root from too few points -> a garbage root
            // and permanent, silent vault loss. Require governance to meet the access quorum.
            if governanceThreshold < accessThreshold { throw SpaceError.policy }
        }
    }

    public struct VaultItem: Equatable {
        public let spaceID: Data
        public let ciphertext: Data
    }

    public final class Space {
        public let spaceID: Data
        public let policy: SpacePolicy
        public private(set) var memberNyms: [Data]
        public private(set) var store: [VaultItem]
        init(spaceID: Data, policy: SpacePolicy, memberNyms: [Data], store: [VaultItem]) {
            self.spaceID = spaceID; self.policy = policy; self.memberNyms = memberNyms; self.store = store
        }
        func append(_ item: VaultItem) { store.append(item) }
        public func isMember(_ nym: Data) -> Bool { memberNyms.contains(nym) }
        public var size: Int { memberNyms.count }
    }

    static let vaultLabel = Data("atlas/space-vault".utf8)

    /// Tenant-isolated vault key: from the space root, namespaced by spaceID.
    public static func vaultKey(spaceRoot: Data, spaceID: Data) -> Data {
        Primitives.hkdf(ikm: spaceRoot, info: vaultLabel + Data("/".utf8) + spaceID, length: 32)
    }

    private static func nym(_ root: Data, _ spaceID: Data) -> Data {
        SpacePseudonym.spaceNym(root: root, spaceID: spaceID)
    }

    private static func reconstruct(_ shares: [Shamir.Share], k: Int, _ err: SpaceError) throws -> Data {
        guard shares.count >= k else { throw err }
        return Shamir.combine(shares)
    }

    public static func createSpace(spaceID: Data, memberRoots: [Data],
                                   policy: SpacePolicy) throws -> (Space, [Data: Shamir.Share]) {
        let n = memberRoots.count
        try policy.validate(n: n)
        let nyms = memberRoots.map { nym($0, spaceID) }
        guard Set(nyms).count == n else { throw SpaceError.duplicateMember }
        let root = Primitives.randomBytes(32)
        let shares = Shamir.split(root, n: n, k: policy.accessThreshold)
        return (Space(spaceID: spaceID, policy: policy, memberNyms: nyms, store: []),
                Dictionary(uniqueKeysWithValues: zip(nyms, shares)))
    }

    @discardableResult
    public static func sealToVault(_ space: Space, plaintext: Data,
                                   presentShares: [Shamir.Share]) throws -> VaultItem {
        let root = try reconstruct(presentShares, k: space.policy.accessThreshold, .access)
        let ct = try Primitives.aeadEncrypt(key: vaultKey(spaceRoot: root, spaceID: space.spaceID),
                                            plaintext: plaintext, aad: space.spaceID)
        let item = VaultItem(spaceID: space.spaceID, ciphertext: ct)
        space.append(item)
        return item
    }

    public static func openVault(_ space: Space, item: VaultItem,
                                 presentShares: [Shamir.Share]) throws -> Data {
        guard item.spaceID == space.spaceID else { throw SpaceError.access }
        let root = try reconstruct(presentShares, k: space.policy.accessThreshold, .access)
        do {
            return try Primitives.aeadDecrypt(key: vaultKey(spaceRoot: root, spaceID: space.spaceID),
                                              blob: item.ciphertext, aad: space.spaceID)
        } catch { throw SpaceError.access }
    }

    private static func reshare(_ space: Space, governanceShares: [Shamir.Share],
                                newMemberRoots: [Data]) throws -> (Space, [Data: Shamir.Share]) {
        let root = try reconstruct(governanceShares, k: space.policy.governanceThreshold, .governance)
        let n = newMemberRoots.count
        try space.policy.validate(n: n)
        let nyms = newMemberRoots.map { nym($0, space.spaceID) }
        guard Set(nyms).count == n else { throw SpaceError.duplicateMember }
        let newShares = Shamir.split(root, n: n, k: space.policy.accessThreshold)
        return (Space(spaceID: space.spaceID, policy: space.policy, memberNyms: nyms, store: space.store),
                Dictionary(uniqueKeysWithValues: zip(nyms, newShares)))
    }

    public static func addMember(_ space: Space, newMemberRoot: Data, currentMemberRoots: [Data],
                                 governanceShares: [Shamir.Share]) throws -> (Space, [Data: Shamir.Share]) {
        guard !space.memberNyms.contains(nym(newMemberRoot, space.spaceID)) else { throw SpaceError.alreadyMember }
        return try reshare(space, governanceShares: governanceShares,
                           newMemberRoots: currentMemberRoots + [newMemberRoot])
    }

    /// Remove a member with TRUE revocation: rotate to a fresh root and re-encrypt the vault, so
    /// every OLD share (removed or retained) decrypts nothing. A plain reshare preserves the root
    /// and is not real revocation.
    public static func removeMember(_ space: Space, targetRoot: Data, remainingMemberRoots: [Data],
                                    governanceShares: [Shamir.Share]) throws -> (Space, [Data: Shamir.Share]) {
        let target = nym(targetRoot, space.spaceID)
        guard space.memberNyms.contains(target) else { throw SpaceError.notMember }
        guard !remainingMemberRoots.map({ nym($0, space.spaceID) }).contains(target) else {
            throw SpaceError.targetStillPresent
        }
        let oldRoot = try reconstruct(governanceShares, k: space.policy.governanceThreshold, .governance)
        let n = remainingMemberRoots.count
        try space.policy.validate(n: n)
        let nyms = remainingMemberRoots.map { nym($0, space.spaceID) }
        guard Set(nyms).count == n else { throw SpaceError.duplicateMember }

        let newRoot = Primitives.randomBytes(32)
        let oldKey = vaultKey(spaceRoot: oldRoot, spaceID: space.spaceID)
        let newKey = vaultKey(spaceRoot: newRoot, spaceID: space.spaceID)
        var rekeyed: [VaultItem] = []
        for item in space.store {
            let pt = try Primitives.aeadDecrypt(key: oldKey, blob: item.ciphertext, aad: space.spaceID)
            let ct = try Primitives.aeadEncrypt(key: newKey, plaintext: pt, aad: space.spaceID)
            rekeyed.append(VaultItem(spaceID: space.spaceID, ciphertext: ct))
        }
        let newShares = Shamir.split(newRoot, n: n, k: space.policy.accessThreshold)
        return (Space(spaceID: space.spaceID, policy: space.policy, memberNyms: nyms, store: rekeyed),
                Dictionary(uniqueKeysWithValues: zip(nyms, newShares)))
    }
}
