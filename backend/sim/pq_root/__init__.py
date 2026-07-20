"""PQ root-of-trust custody topology — pure-Python reference simulation.

This package models the post-quantum ROOT-OF-TRUST custody design for Atlas:

  * An SLH-DSA (SPHINCS+, hash-based) root keypair is generated at GENESIS on a
    computer. The 48-byte SLH-DSA seed is the durable root secret (it
    deterministically regenerates the whole keypair).
  * That seed is SPLIT with Shamir k-of-n across a factor set
    {phone SE, USB, YubiKey} plus a server-SE share.
  * Each share is ML-KEM-wrapped (hybrid X-Wing-style KEM) in transit to its
    holder, so only that holder's secure-element key can unwrap it.
  * The root is reconstructed only transiently for rare continuity events.
  * The computer's copy (seed, sk, raw shares) is WIPED right after genesis; the
    computer holds nothing durable.
  * Re-rooting (a fresh generation) revokes the old root.

It REUSES the real Atlas primitives from backend/atlas/crypto:
  sign.sphincs_*  (real SLH-DSA)   shamir.split/combine   kem.encapsulate/decapsulate
"""
