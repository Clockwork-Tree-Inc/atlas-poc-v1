import Foundation

/// Self-published accreditation — orgs publish their OWN trust edges at their OWN domain. Swift parity
/// with `backend/atlas/interop/trust_publish.py` (Python reference of record).
///
/// An org serves a signed `TrustBundle` at `https://<domain>/.well-known/atlas-trust.json`: the
/// accreditations it HOLDS and the ones it ISSUES. Anyone fetches it, verifies it, and folds the edges
/// into their own `TrustGraph`. No central registry — every edge is independently signature-checked, so
/// an org cannot forge an accreditation it never received, and the bundle signature binds the whole
/// collection to the publishing key + domain. The signed body is length-prefixed field concatenation
/// (not JSON), so a bundle signed by the app verifies on the backend and vice versa.
public enum TrustPublish {

    public static let wellKnownTrust = "/.well-known/atlas-trust.json"

    public enum TrustPublishError: Error { case invalidEdge, edgeNotAboutPublisher, malformed, verificationFailed }

    private static func lp(_ b: Data) -> Data {
        var n = UInt32(b.count).bigEndian
        var out = Data()
        withUnsafeBytes(of: &n) { out.append(contentsOf: $0) }
        out.append(b)
        return out
    }

    // MARK: edge serialization (hex fields; the signature travels with each edge)
    static func edgeToDict(_ a: Attestation) -> [String: Any] {
        ["authority_name": a.authorityName, "authority": a.authority.encode().hexString,
         "subject": a.subject.hexString, "claim": a.claim, "epoch": a.epoch, "sig": a.sig.hexString]
    }

    static func edgeFromDict(_ d: [String: Any]) throws -> Attestation {
        guard let name = d["authority_name"] as? String,
              let authHex = d["authority"] as? String,
              let pub = HybridSign.PublicKey(encoded: Data(hex: authHex)),
              let subjHex = d["subject"] as? String,
              let claim = d["claim"] as? String,
              let epoch = d["epoch"] as? Int,
              let sigHex = d["sig"] as? String else { throw TrustPublishError.malformed }
        return Attestation(authorityName: name, authority: pub, subject: Data(hex: subjHex),
                           claim: claim, epoch: epoch, sig: Data(hex: sigHex))
    }

    /// The signed set of edges an org publishes about itself at its domain.
    public struct TrustBundle {
        public let domain: String
        public let publisher: HybridSign.PublicKey   // the org's key — trust binds here; the domain is provenance
        public let edges: [Attestation]
        public var sig: Data = Data()

        /// The SIGNED body — parity with the Python length-prefixed concatenation.
        public func body() -> Data {
            var buf = Data("atlas/trust-bundle/v1".utf8)
            var count = UInt32(edges.count).bigEndian
            withUnsafeBytes(of: &count) { buf.append(contentsOf: $0) }
            buf.append(TrustPublish.lp(Data(domain.utf8)))
            buf.append(TrustPublish.lp(publisher.encode()))
            for e in edges { buf.append(Issuers.credentialID(e)) }
            return Primitives.H(buf)
        }

        /// The static bytes served at the well-known URL (transport envelope).
        public func toJSON() -> Data {
            let obj: [String: Any] = ["domain": domain, "publisher": publisher.encode().hexString,
                                      "edges": edges.map { TrustPublish.edgeToDict($0) }, "sig": sig.hexString]
            return try! JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
        }
    }

    /// Assemble + sign a bundle. Every edge must be validly signed and INVOLVE the publisher.
    public static func buildTrustBundle(publisher: HybridSign.Keypair, domain: String,
                                        edges: [Attestation]) throws -> TrustBundle {
        let pk = publisher.publicKey.encode()
        for e in edges {
            guard verifyAttestation(e) else { throw TrustPublishError.invalidEdge }
            guard e.subject == pk || e.authority.encode() == pk else { throw TrustPublishError.edgeNotAboutPublisher }
        }
        var b = TrustBundle(domain: domain, publisher: publisher.publicKey, edges: edges)
        b.sig = try HybridSign.sign(publisher, b.body())
        return b
    }

    public static func parseTrustBundle(_ data: Data) throws -> TrustBundle {
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let domain = obj["domain"] as? String,
              let pubHex = obj["publisher"] as? String,
              let pub = HybridSign.PublicKey(encoded: Data(hex: pubHex)),
              let edgeDicts = obj["edges"] as? [[String: Any]],
              let sigHex = obj["sig"] as? String else { throw TrustPublishError.malformed }
        let edges = try edgeDicts.map { try edgeFromDict($0) }
        return TrustBundle(domain: domain, publisher: pub, edges: edges, sig: Data(hex: sigHex))
    }

    /// Publisher signature valid, and every edge validly signed AND about the publisher.
    public static func verifyTrustBundle(_ b: TrustBundle) -> Bool {
        guard HybridSign.verify(b.publisher, b.body(), b.sig) else { return false }
        let pk = b.publisher.encode()
        return b.edges.allSatisfy { verifyAttestation($0) && ($0.subject == pk || $0.authority.encode() == pk) }
    }

    public static func trustBundleURL(_ domain: String) -> String {
        "https://" + domain.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + wellKnownTrust
    }

    /// Verify a bundle and fold its edges into the graph. Returns the number of edges loaded.
    @discardableResult
    public static func loadInto(_ graph: TrustGraph, _ bundle: TrustBundle) throws -> Int {
        guard verifyTrustBundle(bundle) else { throw TrustPublishError.verificationFailed }
        for e in bundle.edges { try graph.add(e) }
        return bundle.edges.count
    }

    /// Pull a domain's published bundle and fold it in. `fetch` is injected (real HTTP in the app,
    /// a stub in tests) so this stays testable.
    @discardableResult
    public static func fetchAndLoad(_ graph: TrustGraph, domain: String,
                                    fetch: (String) throws -> Data) throws -> Int {
        try loadInto(graph, try parseTrustBundle(fetch(trustBundleURL(domain))))
    }
}
