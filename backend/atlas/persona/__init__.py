"""Personas — multi-persona identity on one blind System-ID.

Each persona is a top-level compartment that owns its own full stack (vault, messaging, forum),
mutually unlinkable to your other personas and to the real you. One may be certified as the real,
verified you; the rest stay pseudonymous. See `persona.py`."""

from .persona import (
    PERSONA_SELECTOR_SALT,
    Persona,
    open_persona,
    persona_selector,
)

__all__ = [
    "PERSONA_SELECTOR_SALT",
    "Persona",
    "open_persona",
    "persona_selector",
]
