"""Provenanced office / document layer — a pluggable EDITOR INTEROP SEAM, security-gated.

Any editor can plug in — OnlyOffice ships as the default; third-party editors/apps can too — BUT
only if it clears the security bar: **signed + sandboxed + egress-gated** (not an open-web browser,
not over-privileged). An editor that would be a security threat is refused. This is the same
admission pattern as the AI model gate, and it's how "leave an interop seam" stays safe (and is the
hook for certifying third-party apps).

Whatever editor is admitted, the document is PROVENANCED BY CONSTRUCTION: every edit appends to the
shared `ProvenanceTrail` (author, time, a change *commitment* — never raw content — and whether the
span is human- or AI-authored, with the AI's model + cited sources). So the artifact carries a
verifiable authorship + edit history, and an export (PDF included) can embed a C2PA manifest +
signature + anchor.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .ai.trail import ProvenanceTrail
from .ledger.backend import LedgerBackend


def _h(*parts: bytes) -> bytes:
    m = hashlib.sha3_256()
    for p in parts:
        m.update(len(p).to_bytes(4, "big"))
        m.update(p)
    return m.digest()


# ------------------------------- editor interop seam --------------------------

class EditorRefused(Exception):
    """An editor that doesn't meet the security bar is refused admission to the seam."""


@dataclass(frozen=True)
class EditorSpec:
    name: str
    signed: bool          # code is Atlas-signed / version-pinned (not arbitrary web)
    sandboxed: bool       # runs in a locked runtime — no open-web navigation
    egress_gated: bool    # network only via the Atlas gateway (no open web)


def admit_editor(spec: EditorSpec) -> None:
    """Security gate for the interop seam: signed + sandboxed + egress-gated, or refused."""
    if not (spec.signed and spec.sandboxed and spec.egress_gated):
        raise EditorRefused(
            f"{spec.name} fails the security bar (needs signed + sandboxed + egress-gated)"
        )


# The default shipped editor — a compliant EditorSpec (real OnlyOffice UI integration is app-side).
ONLYOFFICE = EditorSpec("OnlyOffice", signed=True, sandboxed=True, egress_gated=True)


# ------------------------------- provenanced document -------------------------

@dataclass(frozen=True)
class Edit:
    author: str
    kind: str                       # "human" | "ai"
    content_hash: bytes             # commitment to the content after this edit
    model_hash: bytes = b""         # if kind == "ai": which (open, verifiable) model
    sources: Tuple[str, ...] = ()   # if kind == "ai": grounded cited sources


@dataclass
class ProvenancedDocument:
    doc_id: bytes
    editor: EditorSpec
    trail: ProvenanceTrail = field(default_factory=ProvenanceTrail)
    edits: List[Edit] = field(default_factory=list)
    _content: bytes = b""

    def __post_init__(self) -> None:
        admit_editor(self.editor)   # only a compliant editor can open/produce a document

    def apply_edit(self, *, author: str, content: bytes, kind: str = "human",
                   model_hash: bytes = b"", sources: Tuple[str, ...] = ()) -> Edit:
        """Record an edit. Human or AI; AI edits carry the model + grounded sources. The trail gets
        a commitment to (author, kind, content-hash, model, sources) — content stays private."""
        if kind not in ("human", "ai"):
            raise ValueError("kind must be 'human' or 'ai'")
        self._content = content
        ch = _h(self.doc_id, content)
        e = Edit(author, kind, ch, model_hash, tuple(sources))
        self.edits.append(e)
        src = b"".join(s.encode() for s in e.sources)
        self.trail.append("edit", author, _h(kind.encode(), ch, model_hash, src))
        return e

    def export_manifest(self) -> Dict[str, object]:
        """The metadata a PDF/C2PA export embeds: authorship, human-vs-AI breakdown, AI citations,
        and the trail head (which is anchorable → tamper-evident, non-repudiable)."""
        human = sum(1 for e in self.edits if e.kind == "human")
        ai = sum(1 for e in self.edits if e.kind == "ai")
        cited = sorted({s for e in self.edits if e.kind == "ai" for s in e.sources})
        return {
            "doc_id": self.doc_id.hex(),
            "editor": self.editor.name,
            "authors": sorted({e.author for e in self.edits}),
            "edits": len(self.edits),
            "human_edits": human,
            "ai_edits": ai,
            "ai_citations": cited,
            "content_hash": _h(self.doc_id, self._content).hex(),
            "trail_head": self.trail.head().hex(),
        }

    def verify(self) -> bool:
        return self.trail.verify_chain()

    def anchor(self, backend: LedgerBackend, *, epoch_round: bytes):
        """Anchor the document's trail head — immutable, tamper-evident checkpoint of its lineage."""
        return self.trail.anchor(backend, owner_id=self.doc_id, epoch_round=epoch_round)
