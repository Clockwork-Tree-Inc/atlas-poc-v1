"""Provenanced office layer: security-gated editor interop seam + provenanced-by-construction docs
(edit trail, human-vs-AI tagging, exportable manifest, anchorable)."""
import pytest

from atlas.office import (
    ONLYOFFICE,
    EditorRefused,
    EditorSpec,
    ProvenancedDocument,
    admit_editor,
)
from atlas.ledger.backend import LocalBackend


# ---- editor interop seam: security gate ----

def test_compliant_editor_admitted_threatening_editor_refused():
    admit_editor(ONLYOFFICE)                                  # signed+sandboxed+egress-gated -> ok
    open_web = EditorSpec("RandomWebEditor", signed=False, sandboxed=False, egress_gated=False)
    with pytest.raises(EditorRefused):
        admit_editor(open_web)
    half = EditorSpec("HalfSafe", signed=True, sandboxed=True, egress_gated=False)  # open egress
    with pytest.raises(EditorRefused):
        admit_editor(half)


def test_document_refuses_a_noncompliant_editor():
    bad = EditorSpec("Sketchy", signed=False, sandboxed=True, egress_gated=True)
    with pytest.raises(EditorRefused):
        ProvenancedDocument(doc_id=b"doc-1", editor=bad)


# ---- provenanced by construction ----

def _doc():
    return ProvenancedDocument(doc_id=b"doc-1", editor=ONLYOFFICE)


def test_edits_are_recorded_human_and_ai_tagged():
    d = _doc()
    d.apply_edit(author="p:me", content=b"draft v1")
    d.apply_edit(author="ai:butler", content=b"draft v2 with help", kind="ai",
                 model_hash=b"olmo-open", sources=("author:carnot",))
    assert [e.kind for e in d.edits] == ["human", "ai"]
    assert d.edits[1].sources == ("author:carnot",)
    assert len(d.trail.events("edit")) == 2
    assert d.verify()


def test_bad_edit_kind_rejected():
    d = _doc()
    with pytest.raises(ValueError):
        d.apply_edit(author="p:me", content=b"x", kind="alien")


def test_manifest_reports_authorship_and_human_vs_ai():
    d = _doc()
    d.apply_edit(author="p:me", content=b"a")
    d.apply_edit(author="p:me", content=b"ab")
    d.apply_edit(author="ai:butler", content=b"abc", kind="ai", model_hash=b"olmo",
                 sources=("author:asha", "site:web"))
    m = d.export_manifest()
    assert m["editor"] == "OnlyOffice"
    assert m["human_edits"] == 2 and m["ai_edits"] == 1
    assert m["ai_citations"] == ["author:asha", "site:web"]   # AI spans carry grounded citations
    assert set(m["authors"]) == {"p:me", "ai:butler"}
    assert m["trail_head"] == d.trail.head().hex()


def test_tamper_evident_and_anchorable():
    d = _doc()
    d.apply_edit(author="p:me", content=b"one")
    d.apply_edit(author="p:me", content=b"two")
    assert d.verify()
    b = LocalBackend()
    d.anchor(b, epoch_round=(1).to_bytes(8, "big"))
    assert b.latest(b"doc-1") == d.trail.head()               # lineage anchored, immutable
    # tamper a trail event -> chain breaks
    d.trail._events[0] = d.trail._events[0].__class__(
        kind="edit", actor="p:forger", payload=d.trail._events[0].payload,
        prev=d.trail._events[0].prev)
    assert not d.verify()
