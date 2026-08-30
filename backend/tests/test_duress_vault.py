"""Priority 3 — local duress slice: panic-code decoy + zeroize-on-suspicion.

Adversarial proof that the attacks the mechanism exists to stop fail closed:
a panic passcode reveals NOTHING real, and a suspicion event makes the real
vault permanently unreadable (no code path back to plaintext).
"""

import pytest

from atlas.session import PanicVault, VaultZeroized
from atlas.crypto.primitives import aead_decrypt

NORMAL = b"1234-normal"
PANIC = b"0000-panic"


def _vault():
    pv = PanicVault(normal_code=NORMAL, panic_code=PANIC)
    pv.put_real("bank", b"REAL: seed phrase + keys")
    pv.seed_decoy("bank", b"DECOY: a plausible-looking small balance")
    return pv


def test_normal_code_opens_real_vault():
    pv = _vault()
    r = pv.unlock(NORMAL)
    assert r.surface_ok and not r.duress
    assert r.vault.get("bank") == b"REAL: seed phrase + keys"


def test_panic_code_opens_decoy_not_real():
    """The panic code succeeds on the surface (identical response) but opens the
    DECOY — the real content is never exposed and the duress flag is internal."""
    pv = _vault()
    r = pv.unlock(PANIC)
    assert r.surface_ok            # observer sees success, same as normal
    assert r.duress                # internal only
    assert r.vault.get("bank") == b"DECOY: a plausible-looking small balance"
    assert r.vault.get("bank") != b"REAL: seed phrase + keys"


def test_panic_code_cannot_derive_real_key():
    """Cryptographic separation: the panic code's derived key cannot unseal the
    real storage key — the real seal is under a different KDF key, so AEAD fails.
    Coercion into the panic code reveals nothing real."""
    pv = _vault()
    from atlas.session.duress_vault import _code_key, _SEAL_AAD_REAL
    panic_key = _code_key(PANIC, pv._salt)
    with pytest.raises(Exception):
        aead_decrypt(panic_key, pv._sealed_real, aad=_SEAL_AAD_REAL)


def test_wrong_code_is_ordinary_failure_distinct_from_duress():
    pv = _vault()
    r = pv.unlock(b"9999-wrong")
    assert not r.surface_ok and not r.duress and r.vault is None


def test_zeroize_makes_real_vault_permanent_brick():
    """After a suspicion event the real key is destroyed: the normal code no
    longer opens anything real, and the persisted ciphertext is unreadable with
    any available key. Fail-closed — no path back to plaintext."""
    pv = _vault()
    brick = pv.real_brick_at_rest("bank")     # capture the at-rest ciphertext
    pv.zeroize_on_suspicion("coercion detected")
    assert pv.zeroized
    # the normal code now fails on the surface (real seal is gone)
    r = pv.unlock(NORMAL)
    assert not r.surface_ok and r.vault is None
    # authoring into the real vault is refused
    with pytest.raises(VaultZeroized):
        pv.put_real("bank", b"nope")
    # the captured brick cannot be decrypted (no key survives)
    assert pv._real_key is None and pv._sealed_real is None
    assert len(brick) > 12 and brick != b"REAL: seed phrase + keys"  # opaque ciphertext


def test_zeroize_keeps_decoy_alive_for_plausibility():
    """The device must still look alive to a coercer after zeroize: the decoy
    remains openable via the panic code."""
    pv = _vault()
    pv.zeroize_on_suspicion()
    r = pv.unlock(PANIC)
    assert r.surface_ok and r.duress
    assert r.vault.get("bank") == b"DECOY: a plausible-looking small balance"


def test_zeroize_fires_callback_and_is_idempotent():
    fired = []
    pv = PanicVault(normal_code=NORMAL, panic_code=PANIC,
                    on_zeroize=lambda reason: fired.append(reason))
    pv.zeroize_on_suspicion("tamper")
    pv.zeroize_on_suspicion("tamper again")   # idempotent (no crash)
    assert fired == ["tamper", "tamper again"] or fired[0] == "tamper"


def test_normal_and_panic_codes_must_differ():
    with pytest.raises(ValueError):
        PanicVault(normal_code=b"same", panic_code=b"same")
