import Foundation

/// Cross-boundary permissioned grants — the Atlas authority engine (Phase D). Mirrors
/// `backend/atlas/authority/grants.py` byte-for-byte on the canonical encoding (the parity surface).
///
/// Capability-based authorization: a `Grant` is a SIGNED, delegatable statement rooted at a
/// resource's controller; access = a CHAIN of grants back to that root. Rooted, monotonically
/// attenuating, signature-chained, revocable (authenticated), personhood-gated, with proof-of-
/// possession at use. See `AUTHORITY_MODEL.md`. Not new crypto — the macaroon / SPKI model.
public enum Authority {

    public static let ROOT = Data(repeating: 0, count: 32)
    public static let accountable = "accountable"

    static let grantDomain = Data("atlas/authority/grant/v1".utf8)
    static let rotateDomain = Data("atlas/authority/rotate/v1".utf8)
    static let revokeDomain = Data("atlas/authority/revoke/v1".utf8)
    static let grantIdDomain = Data("atlas/authority/grant-id".utf8)

    public enum AuthorityError: Error, Equatable { case fail(String) }

    // length-prefix framing (A11), identical to grants.py `_lp`.
    static func lp(_ d: Data) -> Data {
        var n = UInt32(d.count).bigEndian
        var out = Data(); withUnsafeBytes(of: &n) { out.append(contentsOf: $0) }
        out.append(d); return out
    }
    static func u32(_ v: Int) -> Data { var n = UInt32(v).bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }
    static func u64(_ v: UInt64) -> Data { var n = v.bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }

    // MARK: - rights

    public struct RightSet: Equatable, Hashable {
        public let level: Int
        public let flags: Set<String>
        public init(_ level: Int, _ flags: Set<String> = []) { self.level = level; self.flags = flags }

        /// <= on BOTH axes — the attenuation partial order.
        public func isSubset(of o: RightSet) -> Bool { level <= o.level && flags.isSubset(of: o.flags) }

        public func encode() -> Data {
            var f = Data(); for x in flags.sorted() { f.append(lp(Data(x.utf8))) }
            return u32(level) + lp(f)
        }
    }

    public struct Caveat: Equatable, Hashable {
        public let key: String
        public let value: String
        public init(_ key: String, _ value: String) { self.key = key; self.value = value }
        public func encode() -> Data { lp(Data(key.utf8)) + lp(Data(value.utf8)) }
    }

    // MARK: - grant

    public struct Grant {
        public var grantor: HybridSign.PublicKey
        public var grantee: HybridSign.PublicKey
        public var resource: Data
        public var rights: RightSet
        public var caveats: Set<Caveat>
        public var delegableDepth: Int
        public var parent: Data
        public var epoch: UInt64
        public var sig: Data = Data()
        // FS membership proof — set ONLY on a ROOT grant from a forward-secure signer (issueFS).
        // Proves the signing leaf (grantor) is the FS root's epoch-`fsEpoch` leaf. NOT in body().
        public var fsEpoch: Int? = nil
        public var fsAuthPath: [Data]? = nil

        public func body() -> Data {
            Authority.grantBody(grantorEnc: grantor.encode(), granteeEnc: grantee.encode(),
                                resource: resource, rights: rights, caveats: caveats,
                                depth: delegableDepth, parent: parent, epoch: epoch)
        }
        public func grantId() -> Data { Primitives.H(grantIdDomain, body()) }
    }

    /// Canonical body assembly from RAW encoded components (the parity-critical glue). Kept separate
    /// so parity vectors can pin it with fixed public-key bytes, independent of keygen.
    public static func grantBody(grantorEnc: Data, granteeEnc: Data, resource: Data, rights: RightSet,
                                 caveats: Set<Caveat>, depth: Int, parent: Data, epoch: UInt64) -> Data {
        var cav = Data()
        for c in caveats.sorted(by: { ($0.key, $0.value) < ($1.key, $1.value) }) { cav.append(c.encode()) }
        var out = Data()
        out.append(grantDomain)
        out.append(lp(grantorEnc))
        out.append(lp(granteeEnc))
        out.append(lp(resource))
        out.append(lp(rights.encode()))
        out.append(lp(cav))
        out.append(u32(depth))
        out.append(lp(parent))
        out.append(u64(epoch))
        return out
    }

    public static func grantId(grantorEnc: Data, granteeEnc: Data, resource: Data, rights: RightSet,
                               caveats: Set<Caveat>, depth: Int, parent: Data, epoch: UInt64) -> Data {
        Primitives.H(grantIdDomain, grantBody(grantorEnc: grantorEnc, granteeEnc: granteeEnc,
                                              resource: resource, rights: rights, caveats: caveats,
                                              depth: depth, parent: parent, epoch: epoch))
    }

    // MARK: - rotation + revocation

    public struct RotationCert {
        public var resource: Data
        public var oldRoot: HybridSign.PublicKey
        public var newRoot: HybridSign.PublicKey
        public var epoch: UInt64
        public var sig: Data = Data()
        public init(resource: Data, oldRoot: HybridSign.PublicKey, newRoot: HybridSign.PublicKey,
                    epoch: UInt64, sig: Data = Data()) {
            self.resource = resource; self.oldRoot = oldRoot; self.newRoot = newRoot; self.epoch = epoch; self.sig = sig
        }
        public func body() -> Data {
            rotateDomain + lp(resource) + lp(oldRoot.encode()) + lp(newRoot.encode()) + u64(epoch)
        }
    }

    public struct Revocation {
        public var target: Data
        public var revoker: HybridSign.PublicKey
        public var epoch: UInt64
        public var sig: Data = Data()
        public func body() -> Data { revokeDomain + lp(target) + lp(revoker.encode()) + u64(epoch) }
    }

    // MARK: - issue / delegate / revoke

    public static func issue(root: HybridSign.Keypair, grantee: HybridSign.PublicKey, resource: Data,
                             rights: RightSet, caveats: [Caveat] = [], delegableDepth: Int = 0,
                             epoch: UInt64 = 0) throws -> Grant {
        var g = Grant(grantor: root.publicKey, grantee: grantee, resource: resource, rights: rights,
                      caveats: Set(caveats), delegableDepth: delegableDepth, parent: ROOT, epoch: epoch)
        g.sig = try HybridSign.sign(root, g.body())
        return g
    }

    public static func delegate(_ parent: Grant, holder: HybridSign.Keypair, grantee: HybridSign.PublicKey,
                                rights: RightSet, addCaveats: [Caveat] = [], epoch: UInt64 = 0) throws -> Grant {
        if holder.publicKey.encode() != parent.grantee.encode() {
            throw AuthorityError.fail("only the parent's grantee may delegate it (I5)")
        }
        if parent.delegableDepth < 1 { throw AuthorityError.fail("parent grant is not delegable (I3)") }
        if !rights.isSubset(of: parent.rights) { throw AuthorityError.fail("delegated rights must be a subset of the parent's (I2)") }
        var g = Grant(grantor: parent.grantee, grantee: grantee, resource: parent.resource, rights: rights,
                      caveats: parent.caveats.union(addCaveats), delegableDepth: parent.delegableDepth - 1,
                      parent: parent.grantId(), epoch: epoch)
        g.sig = try HybridSign.sign(holder, g.body())
        return g
    }

    /// Issue a ROOT grant from a FORWARD-SECURE signer (the A13 fix). Signed by the signer's current
    /// epoch leaf; carries a Merkle membership proof (fsEpoch + fsAuthPath) binding the leaf to the FS
    /// root. Verified via verifyChain(fsRoot:). A compromised signer can only sign at the current epoch
    /// and cannot reconstruct a past leaf, so it cannot backdate.
    public static func issueFS(_ signer: FSSign.FSSigner, grantee: HybridSign.PublicKey, resource: Data,
                               rights: RightSet, caveats: [Caveat] = [], delegableDepth: Int = 0,
                               epoch: UInt64 = 0) throws -> Grant {
        let leafPub = try HybridSign.keypair(fromSeed: FSSign.leafSeed(signer.state)).publicKey
        var g = Grant(grantor: leafPub, grantee: grantee, resource: resource, rights: rights,
                      caveats: Set(caveats), delegableDepth: delegableDepth, parent: ROOT, epoch: epoch)
        let fsSig = try signer.sign(g.body())
        g.sig = fsSig.sig
        g.fsEpoch = fsSig.epoch
        g.fsAuthPath = fsSig.authPath
        return g
    }

    public static func revoke(_ target: Grant, revoker: HybridSign.Keypair, epoch: UInt64 = 0) throws -> Revocation {
        var r = Revocation(target: target.grantId(), revoker: revoker.publicKey, epoch: epoch)
        r.sig = try HybridSign.sign(revoker, r.body())
        return r
    }

    // MARK: - verify

    /// The current legitimate root pubkey-encodings for `resource`, each mapped to the epoch its
    /// authority ENDS (`.max` = current root, no cutoff). A rotated-out old root is valid only for
    /// grants with `epoch <= cutoff` (A13 compromise recovery).
    static func rootAuthority(resource: Data, knownRoot: HybridSign.PublicKey,
                              rotations: [RotationCert]) -> [Data: UInt64] {
        var authority: [Data: UInt64] = [knownRoot.encode(): UInt64.max]
        var changed = true
        while changed {
            changed = false
            for r in rotations where r.resource == resource {
                if !HybridSign.verify(r.oldRoot, r.body(), r.sig) { continue }
                if authority[r.newRoot.encode()] != nil && authority[r.oldRoot.encode()] == nil {
                    authority[r.oldRoot.encode()] = r.epoch
                    changed = true
                }
            }
        }
        return authority
    }

    /// Shared per-grant loop (I1–I11); the root-identity check for chain[0] is supplied by `rootCheck`.
    private static func verifyChainCore(_ chain: [Grant], resource: Data, now: UInt64,
                                        revocations: [Revocation], understoodCaveats: Set<String>,
                                        isVerifiedHuman: ((HybridSign.PublicKey) -> Bool)?,
                                        rootCheck: (Grant) throws -> Void) throws -> RightSet {
        if chain.isEmpty { throw AuthorityError.fail("empty chain") }
        let validRevs = revocations.filter { HybridSign.verify($0.revoker, $0.body(), $0.sig) }
        let knownCaveats = understoodCaveats.union(["expiry"])
        var prev: Grant? = nil
        for (i, g) in chain.enumerated() {
            if g.resource != resource { throw AuthorityError.fail("grant \(i): resource mismatch") }
            if !HybridSign.verify(g.grantor, g.body(), g.sig) { throw AuthorityError.fail("grant \(i): bad signature") }
            for c in g.caveats where !knownCaveats.contains(c.key) {
                throw AuthorityError.fail("grant \(i): unrecognized caveat '\(c.key)' — fail closed (A16)")
            }
            for c in g.caveats where c.key == "expiry" {
                if let exp = UInt64(c.value), now > exp { throw AuthorityError.fail("grant \(i): expired") }
            }
            let gid = g.grantId()
            var line = Set<Data>(); for j in 0...i { line.insert(chain[j].grantor.encode()) }
            if validRevs.contains(where: { $0.target == gid && line.contains($0.revoker.encode()) }) {
                throw AuthorityError.fail("grant \(i): revoked")
            }
            if i == 0 {
                if g.parent != ROOT { throw AuthorityError.fail("chain[0] is not a root grant") }
                try rootCheck(g)
            } else {
                let p = prev!
                if g.parent != p.grantId() { throw AuthorityError.fail("grant \(i): parent hash mismatch (A6)") }
                if g.grantor.encode() != p.grantee.encode() { throw AuthorityError.fail("grant \(i): grantor is not the parent's grantee (I5)") }
                if p.delegableDepth < 1 { throw AuthorityError.fail("grant \(i): parent not delegable (A4)") }
                if g.delegableDepth != p.delegableDepth - 1 { throw AuthorityError.fail("grant \(i): delegation depth must decrement by one (A4)") }
                if !g.rights.isSubset(of: p.rights) { throw AuthorityError.fail("grant \(i): rights escalate beyond parent (A1)") }
                if !p.caveats.isSubset(of: g.caveats) { throw AuthorityError.fail("grant \(i): caveats were dropped (A10)") }
            }
            if g.rights.flags.contains(accountable) {
                if isVerifiedHuman == nil || !(isVerifiedHuman!(g.grantee)) {
                    throw AuthorityError.fail("grant \(i): accountable right to an unverified grantee (A9)")
                }
            }
            prev = g
        }
        return prev!.rights
    }

    /// Classic HybridSig root (no forward security; a rotated-out root is retired — A13 interim).
    /// NOT an access gate on its own (A14) — use `verifyAccess`.
    public static func verifyChain(_ chain: [Grant], resource: Data, resourceRoot: HybridSign.PublicKey,
                                   now: UInt64, revocations: [Revocation] = [],
                                   understoodCaveats: Set<String> = [],
                                   isVerifiedHuman: ((HybridSign.PublicKey) -> Bool)? = nil,
                                   rotations: [RotationCert] = []) throws -> RightSet {
        try verifyChainCore(chain, resource: resource, now: now, revocations: revocations,
                            understoodCaveats: understoodCaveats, isVerifiedHuman: isVerifiedHuman) { g in
            let authority = rootAuthority(resource: resource, knownRoot: resourceRoot, rotations: rotations)
            guard let cutoff = authority[g.grantor.encode()] else {
                throw AuthorityError.fail("chain[0] grantor is not the resource root (A12)")
            }
            if cutoff != .max {
                throw AuthorityError.fail("chain[0] root is rotated out / retired — re-issue under the new root (A13 open)")
            }
        }
    }

    /// FORWARD-SECURE root (the A13 fix): chain[0]'s signing leaf (grantor) must be in the FS root tree
    /// at its epoch (Merkle membership). A compromised current signer cannot backdate — it can't
    /// reconstruct a past leaf's secret, and the epoch is bound by the leaf's tree position.
    public static func verifyChain(_ chain: [Grant], resource: Data, fsRoot: FSSign.FSPublicKey,
                                   now: UInt64, revocations: [Revocation] = [],
                                   understoodCaveats: Set<String> = [],
                                   isVerifiedHuman: ((HybridSign.PublicKey) -> Bool)? = nil) throws -> RightSet {
        try verifyChainCore(chain, resource: resource, now: now, revocations: revocations,
                            understoodCaveats: understoodCaveats, isVerifiedHuman: isVerifiedHuman) { g in
            guard let ep = g.fsEpoch, let path = g.fsAuthPath else {
                throw AuthorityError.fail("root grant under an FS root must carry an FS membership proof")
            }
            guard ep >= 0, ep < (1 << fsRoot.height) else { throw AuthorityError.fail("FS epoch out of range") }
            guard path.count == fsRoot.height else { throw AuthorityError.fail("FS auth path wrong length") }
            let lh = FSSign.leafHash(g.grantor.encode())
            if FSSign.rootFromPath(lh, ep, path) != fsRoot.root {
                throw AuthorityError.fail("root grant's signing leaf is not in the FS root tree at that epoch (A13)")
            }
        }
    }

    /// The ACCESS GATE (A14): verify the chain AND require the presenter to prove possession of the
    /// leaf grantee's key by signing a fresh single-use `challenge`.
    public static func verifyAccess(_ chain: [Grant], challenge: Data, proof: Data, now: UInt64,
                                    resource: Data, resourceRoot: HybridSign.PublicKey,
                                    revocations: [Revocation] = [], understoodCaveats: Set<String> = [],
                                    isVerifiedHuman: ((HybridSign.PublicKey) -> Bool)? = nil,
                                    rotations: [RotationCert] = []) throws -> RightSet {
        let rights = try verifyChain(chain, resource: resource, resourceRoot: resourceRoot, now: now,
                                     revocations: revocations, understoodCaveats: understoodCaveats,
                                     isVerifiedHuman: isVerifiedHuman, rotations: rotations)
        guard let leaf = chain.last, HybridSign.verify(leaf.grantee, challenge, proof) else {
            throw AuthorityError.fail("proof-of-possession failed (A14)")
        }
        return rights
    }
}
