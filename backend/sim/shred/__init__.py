"""User-rights (UNLINK + DELETE) — pure-Python reference simulation.

Validates two additions to the Atlas identity model against an APPEND-ONLY
registry that physically cannot delete rows:

  * UNLINK (re-rooting / forward-heal): the user re-roots their System-ID to a
    new generation; new-generation pseudonyms are unlinkable from old-generation
    ones without the secret, while old pseudonyms still resolve to the old
    generation (forward-heal only — the honest bound from §5).

  * DELETE (crypto-shredding): the user destroys the secret OPENING of a
    persisted registry commitment. The append-only row REMAINS, but with the
    opening gone the commitment becomes a meaningless, unlinkable orphan — no
    party (including the operator or the user) can ever re-open or link it. This
    is right-to-erasure realised as key-destruction rather than row-deletion.

It MIRRORS the real Atlas model (backend/atlas/keys/identity.py and
backend/atlas/realid/rerooting.py):

  * pseudonyms are forward-derived from a blind System-ID secret via HKDF
    (the same PRF construction as IdentityTree.pseudonym), and
  * re-rooting rotates the System-ID generation (rotation+1) so the whole
    pseudonym set rotates, exactly like reroot_system_id / build_identity_tree.

It REUSES the real Atlas primitives from backend/atlas/crypto.primitives:
  H (SHA3-256), hkdf (HKDF<SHA-256>), aead_encrypt/aead_decrypt (AES-256-GCM),
  random_bytes (OS CSPRNG).
"""
