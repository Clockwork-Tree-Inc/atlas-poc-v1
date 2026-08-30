import Foundation

/// did:cid exposer — present an Atlas identity as a self-certifying, content-addressed DID so it
/// resolves in the broader ecosystem (DIF Universal Resolver) without a server or ledger. Byte-for-
/// byte parity with `backend/atlas/did_cid.py` (Python is reference-of-record).
///
/// A `did:cid` is derived from the HASH of its own verification material — the identifier IS the
/// content, so anyone verifies a DID matches its keys by recomputing the hash. Interop skin only;
/// method/network/mark stay ours. Format: `did:cid:f<hex>` (`f` = multibase base16).
public enum DidCid {

    static let label = Data("atlas/did-cid/v1".utf8)
    static let prefix = "did:cid:f"

    static func lp(_ d: Data) -> Data {
        var n = UInt32(d.count).bigEndian
        return withUnsafeBytes(of: &n) { Data($0) } + d
    }
    static func u32(_ v: Int) -> Data { var n = UInt32(v).bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }

    /// The canonical verification material the DID is addressed to — the SORTED, length-prefixed set
    /// of public keys (order-independent, framed so adjacent keys can't collide).
    public static func canonicalDocument(_ keys: [HybridSign.PublicKey]) -> Data {
        let encs = keys.map { $0.encode() }.sorted { $0.lexicographicallyPrecedes($1) }
        var buf = label + u32(encs.count)
        for e in encs { buf += lp(e) }
        return buf
    }

    public static func didCid(_ keys: [HybridSign.PublicKey]) -> String {
        prefix + Primitives.H(canonicalDocument(keys)).map { String(format: "%02x", $0) }.joined()
    }

    /// Convenience: the did:cid for a single-key identity (a persona / org / space).
    public static func didFor(_ public_: HybridSign.PublicKey) -> String { didCid([public_]) }

    /// Self-certifying check: the DID must equal the hash of its own verification set.
    public static func verifyDid(_ did: String, keys: [HybridSign.PublicKey]) -> Bool {
        did == didCid(keys)
    }
}
