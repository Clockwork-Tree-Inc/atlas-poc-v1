import Foundation

/// Human-readable NAMES -> persona handles: the discovery / naming-registry layer. Mirrors
/// `backend/atlas/names.py`. A persona opt-in publishes a name (its "domain") that resolves to its
/// opaque handle; names are unique (first valid claim holds it) and a claim is SIGNED by the
/// persona's key (you cannot name a handle you don't control). Owners release; governance revokes.
/// Nothing here weakens per-persona unlinkability — only the names a persona chooses to publish
/// become linkable to that persona's handle, and to nothing else.
public enum Names {
    /// The signed body of a name claim — byte-identical to the Python reference `_claim_body`.
    public static func claimBody(name: String, handle: Data, epoch: Int) -> Data {
        Primitives.H(Data("atlas/name/claim".utf8), Data(name.utf8), handle, Data(String(epoch).utf8))
    }

    public struct NameClaim {
        public var name: String
        public var handle: Data
        public var publicKey: HybridSign.PublicKey
        public var epoch: Int
        public var sig: Data = Data()
        public init(name: String, handle: Data, publicKey: HybridSign.PublicKey, epoch: Int, sig: Data = Data()) {
            self.name = name; self.handle = handle; self.publicKey = publicKey; self.epoch = epoch; self.sig = sig
        }
    }

    public static func claimName(_ identity: Child, name: String, epoch: Int = 0) throws -> NameClaim {
        let handle = identity.handle
        var claim = NameClaim(name: name, handle: handle, publicKey: identity.publicKey, epoch: epoch)
        claim.sig = try HybridSign.sign(identity.keypair, claimBody(name: name, handle: handle, epoch: epoch))
        return claim
    }

    /// Valid iff the claim's handle IS the handle of its public key AND the signature is by that
    /// key over (name, handle, epoch) — so a claimant must control the handle it names.
    public static func verifyClaim(_ c: NameClaim) -> Bool {
        guard handleOf(c.publicKey.encode()) == c.handle else { return false }
        return HybridSign.verify(c.publicKey, claimBody(name: c.name, handle: c.handle, epoch: c.epoch), c.sig)
    }

    public final class NameRegistry {
        public enum RegisterError: Error, Equatable { case invalidClaim, revoked, taken }
        private var names: [String: NameClaim] = [:]
        private var revoked: Set<String> = []
        public init() {}

        public func register(_ claim: NameClaim) throws {
            guard verifyClaim(claim) else { throw RegisterError.invalidClaim }
            guard !revoked.contains(claim.name) else { throw RegisterError.revoked }
            if let held = names[claim.name], held.handle != claim.handle { throw RegisterError.taken }
            names[claim.name] = claim
        }

        /// Human-readable name -> the persona's opaque handle (address of its space).
        public func resolve(_ name: String) -> Data? { names[name]?.handle }

        public func release(_ identity: Child, _ name: String) {
            if let held = names[name], held.handle == identity.handle { names[name] = nil }
        }

        public func revoke(_ name: String) { names[name] = nil; revoked.insert(name) }
    }
}
