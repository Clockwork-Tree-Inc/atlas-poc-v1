"""AI integration seam — model-agnostic, local-first, capability-scoped, provenance-emitting.

The model sits behind a PROTOCOL, so any open model (OLMo/Pleias, no permission needed — Apache/MIT)
wires in without changing callers; the reference `StubModel` is deterministic for tests. An `Agent`
is a human-rooted, revocable principal that holds SCOPED CAPABILITIES (grant/revoke access to a
vault or space). Inference is GROUNDED: retrieval returns the actual sources, which the system
ATTACHES to the result (not self-reported by the model), so every output carries verifiable
citations and can only draw on sources the user is licensed to use.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol, Tuple


@dataclass(frozen=True)
class Source:
    """A retrieved source: an item id + the author it belongs to (for attribution + reward).
    `license_ok` = the user holds a license permitting this use (bought it / own it)."""
    item: bytes
    author: str
    license_ok: bool = True


@dataclass(frozen=True)
class InferenceResult:
    output: str
    model_hash: bytes                 # which (open, verifiable) weights produced it
    sources: Tuple[Source, ...]       # GROUNDED citations — what actually fed the model


class Model(Protocol):
    @property
    def weights_hash(self) -> bytes: ...
    @property
    def open_weights(self) -> bool: ...        # weights are open (auditable), not a closed vendor
    @property
    def ethically_sourced(self) -> bool: ...   # trained on consented, provenance-clean data
    def generate(self, prompt: str, context: List[Source]) -> str: ...


class ModelNotEligible(Exception):
    """A model that is not open + fully ethically-sourced is refused — hard rule, no exceptions."""


def admit(model: Model) -> None:
    """OPEN + FULLY ETHICALLY-SOURCED models ONLY. Closed/vendor models are refused on two grounds:
    (1) they can't be provenance-audited, so they can't participate in the citation/credit economy;
    (2) they were trained on scraped, unconsented work — we don't launder or reward that. Which
    models qualify as ethically-sourced is a certification decision (see the cert-authority model)."""
    if not model.open_weights:
        raise ModelNotEligible("closed/vendor model refused — open weights only")
    if not model.ethically_sourced:
        raise ModelNotEligible("model refused — weights open but training data not ethically sourced")


@dataclass
class StubModel:
    """Deterministic reference model — a real OLMo/Pleias (open + ethically-sourced) wires in behind
    the same protocol."""
    _hash: bytes = b"stub-weights-v0"

    @property
    def weights_hash(self) -> bytes:
        return self._hash

    @property
    def open_weights(self) -> bool:
        return True

    @property
    def ethically_sourced(self) -> bool:
        return True

    def generate(self, prompt: str, context: List[Source]) -> str:
        cited = ",".join(s.author for s in context)
        return f"[answer to {prompt!r} from {len(context)} source(s): {cited}]"


@dataclass(frozen=True)
class AccessGrant:
    scope: str
    expires: int


@dataclass
class Agent:
    """A human-rooted, revocable AI principal. `owner` is the human it acts for (accountable);
    it can hold scoped, time-boxed capabilities — one vault-wide agent that manages everything,
    or per-space agents, or an agent granted access to a space only when wanted."""
    handle: str
    owner: str
    _grants: Dict[str, AccessGrant] = field(default_factory=dict)

    def grant(self, scope: str, *, expires: int) -> None:
        self._grants[scope] = AccessGrant(scope, expires)

    def revoke(self, scope: str) -> None:
        self._grants.pop(scope, None)

    def can_access(self, scope: str, *, now: int) -> bool:
        g = self._grants.get(scope)
        return g is not None and g.expires > now


def run_inference(model: Model, prompt: str, retrieval: List[Source]) -> InferenceResult:
    """Grounded inference. First enforces the OPEN + ethically-sourced eligibility rule (closed/vendor
    models are refused). Only license_ok sources are used, and they are ATTACHED to the result
    (grounded citation) rather than left to the model to remember to cite."""
    admit(model)
    usable = [s for s in retrieval if s.license_ok]
    output = model.generate(prompt, usable)
    return InferenceResult(output=output, model_hash=model.weights_hash, sources=tuple(usable))


def web_search(query: str, results: List[Tuple[bytes, str]]) -> List[Source]:
    """Web retrieval as a TOOL — any open model becomes internet-capable via the agent's search
    tool, and each web result is a `Source`, so it is GROUNDED-CITED in the output like any other
    source. `results` = (url, site/author) pairs (a real search backend wires in behind this). Web
    content is public (license_ok=True); attribution is always recorded, payment only if the site
    is an opted-in Atlas author."""
    return [Source(item=url, author=site, license_ok=True) for (url, site) in results]
