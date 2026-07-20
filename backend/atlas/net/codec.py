"""Cross-language wire schema for a provenance bundle (phone -> Mac node).

JSON so the Swift app can produce the SAME shape (the phone-side encoder is the
remaining wiring for the photo path; the message path needs no bundle). Every
byte field is base64. Reconstructs a real `ProvenanceBundle` the node can verify.
"""

from __future__ import annotations

import base64
from typing import Optional

from ..crypto.sign import HybridSigPublic
from ..liveness.attestation import LivenessAttestation
from ..provenance.capture import CaptureMetadata, ProvenanceBundle
from ..provenance.live_binding import LiveProvenanceBinding
from ..provenance.pad import PADResult


def _b(x: bytes) -> str:
    return base64.b64encode(x).decode()


def _u(s: str) -> bytes:
    return base64.b64decode(s)


def _pub_to(p: HybridSigPublic) -> dict:
    return {"mldsa_pk": _b(p.mldsa_pk), "ed_pk": _b(p.ed_pk)}


def _pub_from(d: dict) -> HybridSigPublic:
    return HybridSigPublic(mldsa_pk=_u(d["mldsa_pk"]), ed_pk=_u(d["ed_pk"]))


def bundle_to_json(b: ProvenanceBundle) -> dict:
    return {
        "content_hash": _b(b.content_hash),
        "authorship_handle": _b(b.authorship_handle),
        "authorship_public": _pub_to(b.authorship_public),
        "metadata": {
            "camera_intrinsics": b.metadata.camera_intrinsics,
            "motion": b.metadata.motion,
            "captured_at": b.metadata.captured_at,
            "depth_summary": b.metadata.depth_summary,
        },
        "drand_round": _b(b.drand_round),
        "epoch_randomness": _b(b.epoch_randomness),
        "pad": {
            "passed": b.pad.passed,
            "depth_variance": b.pad.depth_variance,
            "moire_score": b.pad.moire_score,
            "reasons": list(b.pad.reasons),
        },
        "liveness": {
            "drand_round": _b(b.liveness.drand_round),
            "pole_digest": _b(b.liveness.pole_digest),
            "operate": b.liveness.operate,
            "enclave_public": _pub_to(b.liveness.enclave_public),
            "signature": _b(b.liveness.signature),
            "challenge": _b(b.liveness.challenge),
        },
        "signature": _b(b.signature),
        "anchor_index": b.anchor_index,
        "live_binding": (
            None if b.live_binding is None else
            {"session_commit": _b(b.live_binding.session_commit),
             "witness_sig": _b(b.live_binding.witness_sig)}
        ),
    }


def bundle_from_json(d: dict) -> ProvenanceBundle:
    m = d["metadata"]
    p = d["pad"]
    lv = d["liveness"]
    lb = d.get("live_binding")
    return ProvenanceBundle(
        content_hash=_u(d["content_hash"]),
        authorship_handle=_u(d["authorship_handle"]),
        authorship_public=_pub_from(d["authorship_public"]),
        metadata=CaptureMetadata(camera_intrinsics=m["camera_intrinsics"], motion=m["motion"],
                                 captured_at=m["captured_at"], depth_summary=m["depth_summary"]),
        drand_round=_u(d["drand_round"]),
        epoch_randomness=_u(d["epoch_randomness"]),
        pad=PADResult(passed=p["passed"], depth_variance=p["depth_variance"],
                      moire_score=p["moire_score"], reasons=tuple(p.get("reasons", []))),
        liveness=LivenessAttestation(
            drand_round=_u(lv["drand_round"]), pole_digest=_u(lv["pole_digest"]), operate=lv["operate"],
            enclave_public=_pub_from(lv["enclave_public"]), signature=_u(lv["signature"]),
            challenge=_u(lv.get("challenge", ""))),
        signature=_u(d["signature"]),
        anchor_index=d["anchor_index"],
        live_binding=(None if lb is None else
                      LiveProvenanceBinding(session_commit=_u(lb["session_commit"]),
                                            witness_sig=_u(lb["witness_sig"]))),
    )
