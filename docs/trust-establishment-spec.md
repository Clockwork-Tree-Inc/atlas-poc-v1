# Atlas Decentralized Trust Establishment — Specification v0.1

**Status:** Draft for review. This document specifies, in an implementation-independent way, how trust
lists, accreditation, and federations are established **without a central registry and without x509** —
the question ToIP answers one way (a central, fee-bearing authority) and this answers another
(verifier-chosen plural roots, self-published accreditations, offline verification). A conformant,
tested reference implementation exists (Python reference + Swift/blst on-device port); this document is
the normative description of what it does.

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in RFC 2119.

---

## 1. Problem and design principle

A signature over a credential proves *who signed it*, not *whether to trust the signer*. x509 solves the
second problem with a small set of certificate authorities baked into every client. Decentralized
identifiers removed the central CA but left "which issuers do I trust?" unanswered.

**Design principle — Verification, not Authority.** No party is anointed as a global root. Each
**verifier** supplies its own set of trusted root keys. Trust binds to a **key**, never to a display
name. An accreditation is only as good as whether the verifier's own root set reaches it. Roots are
**plural and overlapping**; a ToIP registry, a government body, a university accreditor, and a
press-freedom network may each be a root that a given verifier opts into, with none privileged over the
others.

---

## 2. Terminology

- **Participant** — any typed entity (individual, organization {nonprofit | for-profit}, agent) operating
  under a persona keypair.
- **Issuer / Authority** — a participant that signs attestations. Not a privileged subsystem; just a key.
- **Verifier / Consumer** — the party checking a credential. Owns the trust decision; supplies
  `trusted_roots`.
- **Edge** — a signed attestation from one key about a subject (see §5).
- **Trust bundle** — a signed collection of edges an org self-publishes at its own domain (§6).
- **Remit** — the KIND of authority an edge requires the issuer to be: `accreditor`, `registry`,
  `licensor`.

---

## 3. Identifiers

3.1. **Self-certifying identifier (did:cid).** An identifier that *is* its key: the DID contains (or is
derived from) the public key, so no registry is needed to resolve key material — resolution is a hash
check. Signatures MUST use a post-quantum hybrid: ML-DSA-65 **and** Ed25519 (both MUST verify).

3.2. **Domain binding (did:web).** An org MAY publish a did:web document at
`https://<domain>/.well-known/did.json` carrying the same verification methods as its did:cid, with
`alsoKnownAs` linking the two. This inherits the trust the domain already carries (only the domain's
controller can serve it). Domain binding is OPTIONAL; the key is the identity, the domain is a
human-friendly, TLS-anchored alias.

3.3. **Addressing (`local@place`).** A persona MAY be addressed as `local@place`, resolving to a signed
nameplate at `https://<place>/.well-known/atlas/<local>.json` containing `{key, display_name, receptive
mode, optional trust_bundle, sig}`. The nameplate is signed by the persona key; the host is untrusted.
It carries no mailbox — discovery is stable and public, delivery is separate and MAY rotate.

---

## 4. Attestation object

An **edge** is the atomic signed statement:

```
Attestation {
  authority_name : string     // display label ONLY; trust binds to `authority`
  authority      : PublicKey  // the signing key
  subject        : bytes      // the subject's public-key encoding (so a subject can be a next-hop issuer)
  claim          : string     // see §5
  epoch          : uint        // monotonic validity gate (edge is live iff epoch <= verifier's `now`)
  sig            : bytes       // hybrid signature over body()
}
body() = H("atlas/attestation/v1", authority_name, subject, claim, str(epoch))
```

An attestation is *valid* iff `sig` verifies under `authority`. Validity says nothing about trust —
that is the verifier's separate check (§7). The **credential id** used for revocation is
`H("atlas/credential-id", body())`.

Nodes are identified by public-key encoding, so `subject` in one edge and `authority` in the next share
one namespace — this is what lets the graph chain.

---

## 5. Claim strings (edge types)

| claim | meaning | issuer must hold remit |
|---|---|---|
| `authorizes:<remit>` | grantor delegates a remit downstream | the same remit, or be a trusted root |
| `accredits:<kind>` | authority attests subject is a bona-fide org of `kind` | `accreditor` |
| `registered` or `registered:<number>` | registry registers a legal entity (optionally binding its real-world number) | `registry` |
| `certifies:<qualification>` | a verified org or a licensor certifies a person | verified org OR `licensor` |
| `affiliated:<role>` | a verified org affiliates a person in a role | be a verified org |
| `real-id` | a verifier binds a person to a real-world legal identity (the eID edge) | verifier's `trusted_verifier_keys` |

Remits are delegable: a trusted root issues `authorizes:accreditor` to a national body, which issues it
to a regional one, which issues `accredits:university`. Every hop is signed, revocable, and walkable.

---

## 6. Self-published trust bundle

An org publishes the edges it holds and issues, at its own domain, so anyone can fetch and fold them in.
No central registry.

6.1. **Location.** `https://<domain>/.well-known/atlas-trust.json`.

6.2. **Signed body (canonical, cross-language).** Field concatenation, NOT JSON, so it is byte-identical
across implementations:

```
body = H( "atlas/trust-bundle/v1",
          u32be(len(edges)),
          lp(domain_utf8),
          lp(publisher_pubkey_encoding),
          credential_id(edge_0), credential_id(edge_1), ... )     // 32 bytes each, in order
sig  = Sign(publisher_key, body)          // hybrid
```
where `lp(x) = u32be(len(x)) || x`. The JSON at the URL is a transport envelope only:
`{domain, publisher: hex, edges: [edge_json...], sig: hex}`; key ordering there is not significant.

6.3. **Constraints.** Every edge MUST validly sign, and MUST involve the publisher (as `subject` or as
`authority`) — an org publishes its own accreditations, not arbitrary ones. Because each edge is
independently signature-checked, a malicious host cannot forge an accreditation; it can only withhold or
serve stale data (an availability concern, not a forgery one).

6.4. **Loading.** A consumer fetches the bundle, verifies the publisher signature and every edge, and
folds the edges into its local trust graph. Hosting is untrusted and interchangeable (own domain, a
mirror, or content-addressed); trust comes from the signatures, not the location.

---

## 7. Trust graph resolution (verification procedure)

A verifier holds `trusted_roots` (a set of key encodings), an optional `revoked` set, and a clock `now`.
An edge is *live* iff its credential id ∉ `revoked` and `epoch <= now`. All checks are FAIL-CLOSED and
each success returns the walked **path** (root-first) for audit.

7.1. **has_remit(key, remit).** True iff `key ∈ trusted_roots`, OR a live `authorizes:<remit>` edge names
`key` as subject and its issuer *itself* has that remit (recursively, cycle-guarded).

7.2. **verify_org(org, kind?).** True iff a live `accredits:<kind>` edge names `org`, from an issuer with
`has_remit(accreditor)`, OR a live `registered[:number]` edge from an issuer with `has_remit(registry)`.

7.3. **verify_qualification(person, q).** A live `certifies:<q>` edge whose issuer is a verified org OR
has `has_remit(licensor)`.

7.4. **verify_affiliation(person, org, role).** A live `affiliated:<role>` edge from `org` to `person`,
where `verify_org(org)` holds.

7.5. **has_real_identity(person).** A live `real-id` edge from a key in the verifier's
`trusted_verifier_keys`.

7.6. **Duplicate/impersonation detection.** For a registry number, `registration_conflict(number)` is
true iff more than one distinct org key holds a live `registered:<number>` edge — visible to anyone;
resolved by the registry revoking the impostor.

7.7. **Cross-recognition** falls out for free: two orgs verified under different national roots both
verify for any consumer that trusts both roots. No special logic.

7.8. **Revocation** is forward-effective. §10 specifies unlinkable revocation for anonymous credentials.

**Everything in §7 is OFFLINE and requires no phone-home** once the relevant bundles and the current
revocation anchor are cached.

---

## 8. Verified-human / anonymous credential binding

Trust in §7 is about which issuers a verifier reaches. §8 is how a *person* proves a claim from such an
issuer **without being identified or linked**.

8.1. Credentials are Pointcheval-Sanders anonymous credentials on BLS12-381. A credential signs
`[claim, master_secret]` (or `[claim, master_secret, revocation_handle]` when revocable). The
`master_secret` is the holder's **link secret**, derived from a private root and shared by all the
holder's personas; it is never revealed.

8.2. **Blind pickup.** Issuance MAY be blind: the holder sends a commitment to the master secret with a
Schnorr proof of knowledge; the issuer signs without seeing it. Pickup exposes only a persona, never the
root.

8.3. **Unlinkable showing.** A presentation reveals the claim and proves knowledge of the hidden master
secret in zero knowledge. Two showings are unlinkable, even to the issuer, and displayable from ANY
persona the holder controls.

8.4. **Voluntary linking.** A holder MAY attach a showing to an identity of their choice (a Real-ID
persona, a pen name) with a signature that binds the proof to that identity. It is claim-jack-proof: an
onlooker cannot re-attribute the showing to themselves.

8.5. **Cross-language portability (normative).** The Fiat-Shamir challenge in every proof MUST hash only
G1/G2 group elements and scalars — never target-group (GT) elements. Schnorr commitments MUST therefore
be sent as group elements (a G2 element `R` for the credential proof; a G1 element for the accumulator
membership proof), and the pairing relations MUST be verified as representation-independent equalities.
This makes proofs byte-identical across pairing libraries with different internal field representations,
so a proof generated by one implementation verifies in another with no shared representation.

---

## 9. Consumption bindings

A single presence/credential claim MUST be expressible as, and consumable via, existing rails:
- **W3C Verifiable Credential** (`as_vc`),
- **OpenID Connect** id-token claim (`as_oidc`),
- **C2PA** assertion for content provenance (`as_c2pa_payload`),
- **WebAuthn/FIDO** for a possession+intent factor.

An offline verifier consuming any of these MUST NOT require a call to the issuer or to Atlas.

---

## 10. Revocation

10.1. **Non-anonymous edges** (§5) are revoked by a published set of credential ids (forward-effective).

10.2. **Anonymous credentials** (§8) MUST use a bilinear-map accumulator. The issuer publishes an
accumulator over all non-revoked handles; the holder proves in zero knowledge that its (hidden) handle
is still accumulated, folded into the showing. Revoking a handle updates the accumulator so every
persona's showing of that credential fails at once, unlinkably, verified against the public accumulator
with no issuer secret and no phone-home. The membership proof's Schnorr commitment MUST be a G1 element
(per §8.5).

---

## 11. Interop with ToIP and other authorities

A ToIP trust registry, a government accreditor, or any federation MAY be expressed as a root a verifier
opts into. This spec does not compete with them; it lets a verifier trust several at once and reach an
accreditation through whichever one applies, with none mandatory and no central toll. A conformant
verifier MAY load a ToIP registry as one entry in `trusted_roots`.

---

## 12. Security considerations

- **Anonymity set (k-anonymity).** A showing hides the holder within the crowd matching the disclosed
  attributes. Disclosing narrow or rare attributes shrinks the crowd toward one. Implementations SHOULD
  warn a holder when a disclosure narrows them to a small set, and holders SHOULD use separate personas
  to prevent intersection across contexts.
- **Issuer knowledge.** Blind issuance (§8.2) keeps the root hidden from the issuer; non-blind issuance
  (a Real-ID degree) legitimately reveals the persona to the issuer at pickup but not to later verifiers.
- **Subgroup safety.** Every received group element MUST be checked on-curve AND in the prime-order
  subgroup before use.
- **The root anchor is a human decision.** Trust ultimately rests on the verifier deciding a top key
  (e.g., a national accreditor, a ToIP registry) is legitimate. This is unavoidable in any system; here
  it is plural, replaceable, and never a single mandatory toll booth.
- **Post-quantum posture.** Identifier signatures and key exchange are PQ-hybrid (ML-DSA + Ed25519,
  ML-KEM + X25519). The anonymous-credential unlinkability layer is classical pairing-based crypto; a
  post-quantum anonymous credential is an open area and MUST be swappable behind the credential
  interface when one is standardized.

---

## 13. Open items

- A published, no-phone-home revocation anchor cadence for §10 (periodic accumulator publication).
- Blinded issuance is specified as OPTIONAL; a mandatory-blind profile could be defined.
- Post-quantum anonymous credential (§12) — awaiting a vetted standard.

---

*Reference implementation: a Python reference and a Swift/blst on-device port, both with cross-language
known-answer tests demonstrating byte-identical proofs. This document is the normative description of
that implementation and is offered as a starting draft for a decentralized trust-establishment work
item.*
