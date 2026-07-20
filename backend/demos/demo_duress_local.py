"""ATLAS PoC — local duress slice: panic-code decoy + zeroize-on-suspicion.

The Auracles "under coercion" demo: to an observer the phone unlocks normally;
internally it reveals only a decoy, and a suspicion signal makes the real vault
a permanent brick. Run:  python demos/demo_duress_local.py
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from atlas.session import PanicVault, VaultZeroized


def banner(t):
    print("\n" + "=" * 68 + f"\n{t}\n" + "=" * 68)


def main() -> int:
    banner("ENROL — one normal passcode, one panic passcode")
    pv = PanicVault(normal_code=b"4417-normal", panic_code=b"9021-panic")
    pv.put_real("wallet", b"REAL: 24-word seed + L2 identity keys")
    pv.seed_decoy("wallet", b"DECOY: $38.20 checking balance, no keys")
    print("  real secret sealed under the normal code; decoy pre-seeded.")

    banner("NORMAL — owner unlocks, sees the real vault")
    r = pv.unlock(b"4417-normal")
    print(f"  surface_ok={r.surface_ok}  duress={r.duress}  ->  {r.vault.get('wallet').decode()}")

    banner("COERCION — attacker forces the panic code")
    r = pv.unlock(b"9021-panic")
    print(f"  surface_ok={r.surface_ok}  duress={r.duress} (INTERNAL ONLY)")
    print(f"  observer sees a working vault -> {r.vault.get('wallet').decode()}")
    print("  the real seed was NEVER exposed; panic key cannot unseal the real key.")

    banner("ZEROIZE-ON-SUSPICION — real key destroyed, real vault bricked")
    brick = pv.real_brick_at_rest("wallet")
    pv.zeroize_on_suspicion("coercion detected")
    print(f"  zeroized={pv.zeroized}; persisted ciphertext still on disk ({len(brick)} bytes)")
    r = pv.unlock(b"4417-normal")
    print(f"  normal code now: surface_ok={r.surface_ok} (real seal gone -> no path to plaintext)")
    try:
        pv.put_real("wallet", b"x")
    except VaultZeroized:
        print("  authoring into the real vault -> refused (fail-closed)")
    r = pv.unlock(b"9021-panic")
    print(f"  decoy still opens for plausibility: duress={r.duress} -> {r.vault.get('wallet').decode()}")
    print("\n  => panic reveals only decoy; suspicion makes the real vault unrecoverable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
