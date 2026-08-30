"""Anonymous credentials on the MASTER SECRET — your System-ID root as the link secret.

Settled model: every credential you collect binds to your MASTER SECRET (the System-ID root as a field
element), through whichever persona picks it up. The root is the hidden witness — proven in ZERO
KNOWLEDGE at every showing, never revealed. Because all your credentials share the one master secret you
can display ANY of them from ANY persona you control; nothing auto-appears anywhere, each showing is your
choice, and two showings are unlinkable. Linking two personas (proving they share your root) is a
separate, voluntary act.

This is the standard link-secret anonymous-credential construction (Idemix / AnonCreds / Coconut family)
on the vetted Pointcheval-Sanders backend (ps_credential): the Schnorr proof of the hidden master secret
IS the zero-knowledge proof. Messages signed = [claim, master_secret]; present reveals `claim`, hides
`master_secret`.

Pieces:
  * master_secret(system_id_root) — your link secret; what every credential binds to; never revealed.
  * request(...) / issue_blind(...) / finalize(...) — BLIND pickup: the issuer signs your credential
    WITHOUT ever seeing the master secret (pickup exposes only a persona, never the root).
  * issue(...)          — non-blind pickup, for when the issuer legitimately sees you (a Real-ID degree).
  * present(...)        — anonymous ZK showing from any persona: reveal the claim, hide the root.
  * present_linked(...) — voluntarily attach a showing to a persona / Real-ID you control (claim an
                          award under your name, surface a credential on a chosen face); claim-jack-proof.
  * verify / verify_linked.

HONEST BOUNDS (§11 posture — same discipline as verification.py; do not overclaim):
  * Universal revocation across personas needs an ACCUMULATOR (revoke once -> every showing fails,
    unlinkably, no phone-home). Open problem; the plain published-set of issuers.py does not compose
    with unlinkable showings.
  * Classical BLS12-381 pairings (not post-quantum), from the PS backend. Backend/verifier only — no
    Swift parity (no pairing lib on Swift); anon-cred verification is a server operation.
"""
from __future__ import annotations

from typing import Tuple

from ..crypto.primitives import H
from ..crypto.sign import HybridSigKeypair, HybridSigPublic, sign as _sign, verify as _verify
from . import ps_credential as _ps

# messages = [claim, master_secret]
_MSG_COUNT = 2
_CLAIM_IDX = 0
_SECRET_IDX = 1


def new_issuer() -> _ps.PSSecretKey:
    """A credential issuer (a university, a board, a publisher) — a PS keypair over 2 messages. Its
    public key is what a verifier pins; trusting that key is the consumer's call (verification, not
    authority)."""
    return _ps.ps_keygen(_MSG_COUNT)


def master_secret(system_id_root: bytes) -> int:
    """Your MASTER SECRET (link secret) as a field element, derived from your System-ID root. Every
    credential binds to this; every persona you control shares it; it is proven in zero knowledge and
    NEVER revealed. Binding to the root (not to a persona) is what lets you display any credential from
    any persona while the root stays private."""
    return _ps._hash_to_scalar(b"atlas/anon-accred/master-secret/v1", system_id_root)


def issue(issuer: _ps.PSSecretKey, *, claim: str, master_secret: int) -> _ps.Signature:
    """Non-blind pickup: the issuer signs [claim, master_secret] and DOES see the master secret. Use this
    only when the issuer legitimately identifies you (e.g. a Real-ID degree). For pickup that exposes only
    a persona and never the root, use the blind flow: request -> issue_blind -> finalize."""
    return _ps.ps_sign(issuer, [_ps.msg_scalar(claim), master_secret % _ps.R])


def request(issuer_pk: _ps.PSPublicKey, *, master_secret: int) -> Tuple[_ps.BlindRequest, int]:
    """Holder, blind pickup step 1: build a request that HIDES the master secret behind a commitment +
    proof of knowledge. Only a persona is exposed at pickup; the root never is. Returns (request,
    blinding) — keep the blinding private to finalize."""
    return _ps.blind_request(issuer_pk, {_SECRET_IDX: master_secret % _ps.R})


def issue_blind(issuer: _ps.PSSecretKey, req: _ps.BlindRequest, *, claim: str) -> _ps.Signature:
    """Issuer, blind pickup step 2: verify the proof and blind-sign, disclosing ONLY the claim. The
    issuer never sees the master secret. Returns a blinded signature for the holder to finalize."""
    return _ps.blind_sign(issuer, req, {_CLAIM_IDX: _ps.msg_scalar(claim)})


def finalize(blinded: _ps.Signature, blinding: int) -> _ps.Signature:
    """Holder, blind pickup step 3: unblind into a credential bound to the master secret, ready to
    present exactly like any other — present/present_linked/verify all work unchanged."""
    return _ps.blind_unblind(blinded, blinding)


def present(issuer_pk: _ps.PSPublicKey, credential: _ps.Signature, *, claim: str, master_secret: int,
            nonce: bytes) -> _ps.PSProof:
    """An anonymous zero-knowledge showing, from ANY persona: reveal `claim`, hide the master secret.
    Re-randomized and uncorrelatable each time. Callable by any persona that holds the master secret."""
    messages = [_ps.msg_scalar(claim), master_secret % _ps.R]
    return _ps.ps_present(issuer_pk, credential, messages, reveal=[_CLAIM_IDX], nonce=nonce)


def verify(issuer_pk: _ps.PSPublicKey, proof: _ps.PSProof, *, claim: str, nonce: bytes) -> bool:
    """A verifier's check: a valid PS showing under `issuer_pk` that reveals exactly the expected
    `claim`, and a Schnorr proof of knowledge of the hidden master secret. Learns nothing about who."""
    if proof.reveal != (_CLAIM_IDX,):
        return False
    if len(proof.revealed_vals) != 1 or proof.revealed_vals[0] != _ps.msg_scalar(claim) % _ps.R:
        return False
    return _ps.ps_verify(issuer_pk, proof, nonce)


# --- voluntary: display a credential attached to a persona / Real-ID you choose ---------------------

def _bound_nonce(nonce: bytes, identity: HybridSigPublic) -> bytes:
    """Bind the anon proof to the chosen identity, so a proof made for one identity can't be replayed
    under another (claim-jacking): the proof's nonce folds in the identity's key."""
    return H(b"atlas/anon-accred/link-nonce/v1", nonce, identity.encode())


def _link_transcript(proof: _ps.PSProof, claim: str, nonce: bytes) -> bytes:
    return H(b"atlas/anon-accred/link/v1", _ps.serialize_proof(proof), claim.encode(), nonce)


def present_linked(issuer_pk: _ps.PSPublicKey, credential: _ps.Signature, *, claim: str,
                   master_secret: int, nonce: bytes, identity: HybridSigKeypair
                   ) -> Tuple[_ps.PSProof, HybridSigPublic, bytes]:
    """Display the credential ON WHICHEVER persona (or Real-ID) you choose — collect everything at your
    System-ID's private hub and show any of it where you want: claim a pseudonymously-earned award under
    your real name, or surface a degree on a different face. Anonymity is opt-out per showing: `present`
    stays anonymous, this attaches it to `identity`. Only the master secret can produce the proof, and it
    is bound to this identity, so no one else can attach it to themselves. This is also how you LINK
    personas when you want. Returns (proof, identity_pub, link_sig)."""
    bn = _bound_nonce(nonce, identity.public)
    proof = present(issuer_pk, credential, claim=claim, master_secret=master_secret, nonce=bn)
    return proof, identity.public, _sign(identity, _link_transcript(proof, claim, nonce))


def verify_linked(issuer_pk: _ps.PSPublicKey, proof: _ps.PSProof, *, claim: str, nonce: bytes,
                  identity: HybridSigPublic, link_sig: bytes) -> bool:
    """Verify a linked showing: the anon credential is valid for `claim` AND `identity` signed THIS
    showing. The verifier learns that this specific identity holds the credential — and, because the
    proof's nonce is bound to the identity, a relayed proof can't be re-attributed to someone else."""
    if not verify(issuer_pk, proof, claim=claim, nonce=_bound_nonce(nonce, identity)):
        return False
    return _verify(identity, _link_transcript(proof, claim, nonce), link_sig)
