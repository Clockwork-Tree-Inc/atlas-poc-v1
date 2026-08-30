import Foundation

/// Trust graph — orgs verified by the APPROPRIATE real-world authority, people bound to real-world
/// identities, and everyone linked in ONE signed, walkable graph. Swift parity with
/// `backend/atlas/trust_graph.py` (Python reference of record).
///
/// Assembly layer over `Attestation`: turns isolated "authority X signed a claim about Y" edges into a
/// graph you can WALK. Orgs are verified only by an authority of the RIGHT KIND (an accreditor, itself
/// authorized up to a consumer-trusted root); people are bound to real-world identity (the eID edge)
/// and linked to verified orgs. VERIFICATION-NOT-AUTHORITY: the verifier supplies `trustedRoots`, every
/// check is fail-closed, and every success returns the `Path` it walked. Nodes are identified by their
/// PUBLIC KEY encoding, so an org that is a subject in one edge can be the issuer in the next.
public final class TrustGraph {

    // MARK: remits — what KIND of authority an edge requires the issuer to be
    public static let accreditor = "accreditor"   // entitled to accredit organizations
    public static let registry = "registry"       // entitled to register legal entities
    public static let licensor = "licensor"       // entitled to license/certify individuals

    public enum TrustGraphError: Error { case badSignature }

    // MARK: claim builders
    public static func authorizesClaim(_ remit: String) -> String { "authorizes:\(remit)" }
    public static func accreditsClaim(_ kind: String) -> String { "accredits:\(kind)" }
    public static func certifiesClaim(_ qualification: String) -> String { "certifies:\(qualification)" }
    public static func affiliatedClaim(_ role: String) -> String { "affiliated:\(role)" }

    /// A registry's edge, optionally binding the real-world registry NUMBER — `registered` (bare) or
    /// `registered:<number>`. Binding the number makes a duplicate registration detectable.
    public static func registeredClaim(_ number: String = "") -> String {
        number.isEmpty ? SupplyGate.registrationClaim : "\(SupplyGate.registrationClaim):\(number)"
    }

    /// The real-world number a registration edge binds, or nil for a bare `registered` edge.
    public static func registrationNumber(_ att: Attestation) -> String? {
        if att.claim == SupplyGate.registrationClaim { return nil }
        let prefix = SupplyGate.registrationClaim + ":"
        return att.claim.hasPrefix(prefix) ? String(att.claim.dropFirst(prefix.count)) : nil
    }

    static func isRegistration(_ claim: String) -> Bool {
        claim == SupplyGate.registrationClaim || claim.hasPrefix(SupplyGate.registrationClaim + ":")
    }

    // MARK: edge constructors — the SUBJECT is the subject's key encoding, so an org that is a subject
    //       here can be an issuer in the next hop (this is what lets the graph chain).
    public static func authorize(_ grantor: HybridSign.Keypair, grantee: HybridSign.PublicKey,
                                 remit: String, grantorName: String = "", epoch: Int = 0) throws -> Attestation {
        try issueAttestation(authority: grantor, authorityName: grantorName, subject: grantee.encode(),
                             claim: authorizesClaim(remit), epoch: epoch)
    }

    public static func accredit(_ authority: HybridSign.Keypair, org: HybridSign.PublicKey, kind: String,
                                authorityName: String = "", epoch: Int = 0) throws -> Attestation {
        try issueAttestation(authority: authority, authorityName: authorityName, subject: org.encode(),
                             claim: accreditsClaim(kind), epoch: epoch)
    }

    public static func register(_ registry: HybridSign.Keypair, org: HybridSign.PublicKey, number: String = "",
                                registryName: String = "", epoch: Int = 0) throws -> Attestation {
        try issueAttestation(authority: registry, authorityName: registryName, subject: org.encode(),
                             claim: registeredClaim(number), epoch: epoch)
    }

    public static func certify(_ issuer: HybridSign.Keypair, person: HybridSign.PublicKey, qualification: String,
                               issuerName: String = "", epoch: Int = 0) throws -> Attestation {
        try issueAttestation(authority: issuer, authorityName: issuerName, subject: person.encode(),
                             claim: certifiesClaim(qualification), epoch: epoch)
    }

    public static func affiliate(_ org: HybridSign.Keypair, person: HybridSign.PublicKey, role: String,
                                 orgName: String = "", epoch: Int = 0) throws -> Attestation {
        try issueAttestation(authority: org, authorityName: orgName, subject: person.encode(),
                             claim: affiliatedClaim(role), epoch: epoch)
    }

    /// The eID edge: a trusted verifier binds a person to a real-world legal identity.
    public static func bindRealIdentity(_ verifier: HybridSign.Keypair, person: HybridSign.PublicKey,
                                        verifierName: String = "", epoch: Int = 0) throws -> Attestation {
        try issueAttestation(authority: verifier, authorityName: verifierName, subject: person.encode(),
                             claim: SupplyGate.realIDClaim, epoch: epoch)
    }

    /// The audit trail a verification walked — root-first. Empty means the node WAS the trusted root.
    public struct Path {
        public let edges: [Attestation]
        public init(_ edges: [Attestation] = []) { self.edges = edges }
        public func authorities() -> [String] { edges.map { $0.authorityName } }
    }

    // MARK: state — the verifier owns the trust: it supplies `trustedRoots`, `now` gates validity.
    public private(set) var trustedRoots: Set<Data>
    public var revoked: Set<Data>
    public var now: Int
    private var bySubject: [Data: [Attestation]] = [:]

    public init(trustedRoots: Set<Data>, revoked: Set<Data> = [], now: Int = 0) {
        self.trustedRoots = trustedRoots; self.revoked = revoked; self.now = now
    }

    /// Admit a signature-valid edge (fail-closed on forgery). Trust/time/revocation are walk-time.
    @discardableResult
    public func add(_ att: Attestation) throws -> TrustGraph {
        guard verifyAttestation(att) else { throw TrustGraphError.badSignature }
        bySubject[att.subject, default: []].append(att)
        return self
    }

    /// Publish a revocation (a struck-off accreditor, a rescinded license) — forward-effective.
    public func revoke(_ att: Attestation) { revoked.insert(Issuers.credentialID(att)) }

    private func live(_ att: Attestation) -> Bool {
        !revoked.contains(Issuers.credentialID(att)) && att.epoch <= now
    }

    private func edgesTo(_ subjectKey: Data) -> [Attestation] { bySubject[subjectKey] ?? [] }
    private func allEdges() -> [Attestation] { bySubject.values.flatMap { $0 } }

    // MARK: the walker

    /// Is `authorityKey` entitled to act as `remit`? True if it is a trusted root, or holds an
    /// `authorizes:<remit>` edge from a grantor that ITSELF holds the remit — chaining to a root.
    public func hasRemit(_ authorityKey: Data, _ remit: String, seen: Set<Data> = []) -> Path? {
        if trustedRoots.contains(authorityKey) { return Path() }
        if seen.contains(authorityKey) { return nil }
        let seen2 = seen.union([authorityKey])
        let want = TrustGraph.authorizesClaim(remit)
        for e in edgesTo(authorityKey) where e.claim == want && live(e) {
            if let up = hasRemit(e.authority.encode(), remit, seen: seen2) {
                return Path(up.edges + [e])
            }
        }
        return nil
    }

    /// An org is verified iff an ACCREDITOR accredits it (optionally of a specific `kind`) OR a REGISTRY
    /// registers it, where that authority chains to a trusted root. Returns the Path walked.
    public func verifyOrg(_ org: HybridSign.PublicKey, kind: String? = nil) -> Path? {
        for e in edgesTo(org.encode()) where live(e) {
            if e.claim.hasPrefix("accredits:") && (kind == nil || e.claim == TrustGraph.accreditsClaim(kind!)) {
                if let up = hasRemit(e.authority.encode(), TrustGraph.accreditor) { return Path(up.edges + [e]) }
            } else if TrustGraph.isRegistration(e.claim) {
                if let up = hasRemit(e.authority.encode(), TrustGraph.registry) { return Path(up.edges + [e]) }
            }
        }
        return nil
    }

    /// Every LIVE registration edge that binds real-world `number` (optionally from one registry).
    public func registrationsOf(_ number: String, registryKey: Data? = nil) -> [Attestation] {
        let want = TrustGraph.registeredClaim(number)
        return allEdges().filter { e in
            e.claim == want && live(e) && (registryKey == nil || e.authority.encode() == registryKey)
        }
    }

    /// True if `number` is registered to MORE THAN ONE distinct org key — someone tried to register your
    /// org. Surface it to the rightful holder; the registry revokes the impostor.
    public func registrationConflict(_ number: String, registryKey: Data? = nil) -> Bool {
        Set(registrationsOf(number, registryKey: registryKey).map { $0.subject }).count > 1
    }

    /// True iff `org` is the ONE key holding a live registration for `number` (false when contested).
    public func soleRegistrant(_ org: HybridSign.PublicKey, _ number: String, registryKey: Data? = nil) -> Bool {
        Set(registrationsOf(number, registryKey: registryKey).map { $0.subject }) == [org.encode()]
    }

    /// A person holds `qualification` iff a certifier attests it AND that certifier is either a verified
    /// org (a school certifying its graduate) or a licensor chaining to a root.
    public func verifyQualification(_ person: HybridSign.PublicKey, _ qualification: String) -> Path? {
        let want = TrustGraph.certifiesClaim(qualification)
        for e in edgesTo(person.encode()) where e.claim == want && live(e) {
            if let viaOrg = verifyOrg(e.authority) { return Path(viaOrg.edges + [e]) }
            if let viaLic = hasRemit(e.authority.encode(), TrustGraph.licensor) { return Path(viaLic.edges + [e]) }
        }
        return nil
    }

    /// A person is affiliated to a VERIFIED org in `role` — the org vouches for its own people, and the
    /// org itself must verify.
    public func verifyAffiliation(_ person: HybridSign.PublicKey, org: HybridSign.PublicKey, role: String) -> Path? {
        let want = TrustGraph.affiliatedClaim(role)
        let orgKey = org.encode()
        for e in edgesTo(person.encode()) where e.claim == want && live(e) && e.authority.encode() == orgKey {
            if let up = verifyOrg(org) { return Path(up.edges + [e]) }
        }
        return nil
    }

    /// A person is bound to a real-world identity iff a verifier the consumer trusts issued the eID
    /// (`real-id`) edge and it is live. The person-side symmetric of org accreditation.
    public func hasRealIdentity(_ person: HybridSign.PublicKey, trustedVerifierKeys: Set<Data>) -> Bool {
        edgesTo(person.encode()).contains { e in
            e.claim == SupplyGate.realIDClaim && live(e) && trustedVerifierKeys.contains(e.authority.encode())
        }
    }
}
