# The `did:atlas` Method — DRAFT

**Status: draft, not submitted.** This document describes identifiers that already exist in
this repository (`backend/atlas/keys/identity.py`, `backend/atlas/realid/`) and expresses them
in W3C DID Core terms so that external verifiers, wallets and credential toolchains can consume
them without Atlas-specific code. Where a section describes something **not yet implemented**,
it says so inline.

Nothing here changes the identity architecture. It is a serialisation and a resolution contract
for structure that is already built.

---

## 1. Why a method at all

Atlas already produces self-controlled, key-rooted, per-context identifiers:

```
TSK  (permanent; split user-half + server-HSM-half; never whole post-genesis)
  -> System-ID  (reassembled from BOTH halves; blind, never surfaced)
     -> pseudonyms  (forward-derived; PUBLIC / PRIVATE / ANONYMOUS tier per pseudonym)
```

with `handle_of(public) = H("atlas/handle", public)` as the opaque standing identifier and a
different handle per context (`CHILD_CONTEXTS = real-id, anonymous, authorship, recovery`, plus
per-space pseudonyms).

That is a DID in everything but syntax. Publishing the method costs nothing architecturally and
makes those identifiers legible to every existing VC/wallet/verifier stack.

**Two properties make it worth specifying rather than reusing `did:key`:**

1. **The DID is a commitment, not a key.** The identifier is `H(public)`. The public key is
   revealed only at a continuity event, where the verifier confirms it hashes to the known
   handle and only then verifies the signature. Most methods publish the key in a resolvable
   document; here the document is *committed to*, not published.
2. **Authentication can be liveness-gated.** A verification method may require a fresh presence
   attestation for authentication to succeed. No existing method has a liveness condition.

---

## 2. Method-specific identifier

```
atlas-did    = "did:atlas:" idchar
idchar       = multibase(base58btc, handle)      ; handle = H("atlas/handle", public_encoded)
```

The identifier is the **handle**, not the key. It reveals nothing about the key material, the
subject, or any other identifier held by the same subject.

### 2.1 One subject, many DIDs (normative)

A subject **MUST NOT** be represented by a single global `did:atlas`. Each context gets its own
forward-derived pseudonym and therefore its own DID. Two DIDs held by the same subject **MUST
NOT** be correlatable from the identifiers alone.

The **System-ID is blind and is never expressed as a DID.** There is deliberately no identifier
for "the human"; only for the roles that human presents in a given context.

*(Implemented: `build_identity_tree()`, `realid/space_pseudonym.py`, tier selection per
pseudonym.)*

---

## 3. DID Document

Resolution yields a document whose verification methods are **hybrid post-quantum**:

| Purpose | Key type | Where |
|---|---|---|
| `authentication`, `assertionMethod` | ML-DSA-65 + Ed25519 (`HybridSigPublic`) | `crypto/sign.py` |
| `keyAgreement` | ML-KEM-768 + X25519 | `crypto/kem.py` |
| root / long-lived attestation | SLH-DSA (SPHINCS+) | `keys/identity.py` |

Hybrid verification methods are, as far as we know, not yet expressed by any registered method.
The `publicKeyMultibase` value carries the concatenated hybrid public key; a verifier that
understands only the classical half **MUST** fail closed rather than verify on that half alone.

### 3.1 Liveness-gated authentication *(proposed, not implemented)*

A verification method MAY carry:

```json
{
  "id": "did:atlas:<handle>#auth",
  "type": "AtlasHybridVerificationKey2026",
  "atlas:requiresPresence": {
    "minAssuranceTier": "BOUND",
    "maxAgeSeconds": 30
  }
}
```

Authentication then succeeds only when accompanied by a presence attestation meeting those
constraints. Tiers are those of `attestation/device.py`
(`NONE < PRESENCE < BOUND < ATTESTED < IDENTIFIED`).

This is the property the rest of the ecosystem lacks: a credential proves a key was used; it does
not prove a living, uncoerced human was there when it was used.

---

## 4. Operations

### Create
Derive a pseudonym for the context from the identity tree; the DID is
`did:atlas:` + multibase(`handle_of(public)`). No registration, no ledger, no network call. The
identifier exists the moment the key does.

### Read (resolve)
There is **no global registry** — by design, since a registry is a correlation surface. Two
resolution modes:

- **Self-certifying.** The controller presents the public key; the resolver verifies
  `H("atlas/handle", public) == handle` and constructs the document from it. Trustless, offline,
  no third party. (Compare `did:key`, but hash-committed rather than key-encoded.)
- **Pairwise.** The document is exchanged once, out of band, and cached by the counterparty.
  (Compare `did:peer`.)

A resolver that cannot obtain the public key by either route **MUST** return `notFound` rather
than any partial document.

### Update
Verification material is **forward-derived, not edited.** Rotation is re-rooting
(`realid/rerooting.py`), which produces a new pseudonym and therefore a new DID, with an
attested link to the prior one available *only* to counterparties the subject chooses to inform.
There is no public update log, because a public update log would link the two.

### Deactivate
Revocation through the existing anchor; a deactivated DID resolves to `deactivated: true` for
counterparties holding it pairwise, and self-certifying resolution of a revoked handle fails.

---

## 5. Security considerations

- **The controller is a threshold, not a person.** The TSK is split user-half + server-HSM-half
  and is never whole after genesis; the System-ID is reassembled from both. No single party —
  including the operator — can produce a signature alone.
- **Commitment before reveal.** Because the DID is `H(public)`, an observer who has only seen the
  DID cannot test candidate keys against it without already holding the key.
- **Fail closed on partial verification.** A hybrid verification method verified on only its
  classical half is a downgrade attack. Verifiers MUST reject.
- **Presence is not identity.** A presence attestation says a living human was there. It says
  nothing about *which* human. Tier `IDENTIFIED` is the only rung that involves a bound identity.

## 6. Privacy considerations

- **No global identifier for a human exists in this method.** That is not an omission.
- **No registry, no ledger, no anchoring transaction** — nothing that accumulates a public record
  of when identifiers were created or used.
- **Per-context DIDs are unlinkable from the identifiers alone.** Correlation requires
  cooperation from the subject, or a break of the underlying derivation.
- **Resolution is not observable.** Self-certifying resolution involves no network call, so
  nobody learns that a DID was resolved — unlike methods whose resolution hits a universal
  resolver or a chain.

---

## 7. Relationship to adjacent work

- **KYA-OS / DIF Trusted AI Agents.** Delegation credentials prove an agent is authorised. They
  cannot prove the authorising human was present and uncoerced, at issuance or at exercise. A
  `did:atlas` subject with a liveness-gated verification method supplies exactly that, and the
  authority engine (`authority/grants.py`) already implements attenuated delegation with a
  fail-closed caveat vocabulary — a `presence-required` caveat is the natural expression.
- **C2PA / CAWG.** The same attestation, different vertical: *a live human was present at
  capture*, which is the gap behind the analog-hole problem in content provenance.
- **OpenID4VP.** Transport only; a `did:atlas` subject and a presence attestation ride inside it
  unchanged.

---

## 8. What is implemented today

| Element | State |
|---|---|
| Identity tree, per-context handles, tiers | implemented (`keys/identity.py`) |
| Split TSK, blind System-ID, threshold controller | implemented |
| Hybrid PQC keys (ML-DSA-65+Ed25519, ML-KEM-768+X25519, SPHINCS+ root) | implemented |
| Re-rooting / rotation | implemented (`realid/rerooting.py`) |
| Device assurance tiers | implemented (`attestation/device.py`) |
| `did:atlas` serialisation and resolver | **not implemented** |
| `atlas:requiresPresence` verification-method property | **not implemented, proposed** |
| Presence attestation as a VC | **not implemented, proposed** |
