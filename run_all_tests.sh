#!/usr/bin/env bash
# =============================================================================
# Atlas PoC — one-command test harness.
#
#   Part A (runs anywhere with Python):  backend suite + demos + parity-vector
#                                        freshness check.
#   Part B (runs on a Mac with Swift):   AtlasCore `swift build` + `swift test`
#                                        (the objective cross-impl gate).
#
# Usage:
#   ./run_all_tests.sh            # run everything available on this machine
#   ./run_all_tests.sh backend    # Part A only
#   ./run_all_tests.sh swift      # Part B only
#
# Exit code is non-zero if any run fails. See ios/MAC_TEST_RUNBOOK.md for what
# each Swift failure means and how to clear it.
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$ROOT/backend"
SWIFTPKG="$ROOT/ios/AtlasCore"
WHICH="${1:-all}"

pass=0; fail=0
say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓ %s\033[0m\n' "$*"; pass=$((pass+1)); }
bad()  { printf '  \033[31m✗ %s\033[0m\n' "$*"; fail=$((fail+1)); }

run_backend() {
  say "PART A — Python reference-of-record (backend/)"
  command -v python3 >/dev/null 2>&1 && PY=python3 || PY=python
  if ! command -v "$PY" >/dev/null 2>&1; then bad "python not found"; return; fi

  ( cd "$BACKEND" && "$PY" -m pytest -q ) && ok "backend pytest" || bad "backend pytest"

  # Parity vectors must be current: regenerate and confirm nothing drifted.
  # (A drift here means the Swift bundle is testing against stale vectors.)
  ( cd "$BACKEND" && "$PY" -m tools.gen_parity_vectors >/dev/null ) \
    && ok "parity vectors regenerated" || bad "parity generator failed"
  if git -C "$ROOT" diff --quiet -- backend/parity/parity_vectors.json \
        ios/AtlasCore/Tests/AtlasCoreTests/Resources/parity_vectors.json; then
    ok "parity vectors up to date (Swift bundle matches Python)"
  else
    bad "parity vectors DRIFTED — commit the regenerated JSON before the Swift run"
  fi

  # Demos are executable documentation; a crash is a regression.
  for d in demo_milestone5_photo demo_duress_local demo_ambient_signal demo_population_sim; do
    if [ -f "$BACKEND/demos/$d.py" ]; then
      ( cd "$BACKEND" && "$PY" "demos/$d.py" >/dev/null 2>&1 ) \
        && ok "demo $d" || bad "demo $d"
    fi
  done
}

run_swift() {
  say "PART B — Swift AtlasCore cross-impl gate (ios/AtlasCore/)"
  if ! command -v swift >/dev/null 2>&1; then
    printf '  \033[33m• swift toolchain not found — skipping (run this part on a Mac)\033[0m\n'
    return
  fi
  printf '  toolchain: %s\n' "$(swift --version 2>/dev/null | head -1)"
  ( cd "$SWIFTPKG" && swift build ) && ok "swift build" || {
    bad "swift build — see MAC_TEST_RUNBOOK.md §Known-blockers (likely CryptoKit PQC symbols)"
    return
  }
  ( cd "$SWIFTPKG" && swift test ) && ok "swift test (incl. ParityTests)" \
    || bad "swift test — see MAC_TEST_RUNBOOK.md §Interpreting-failures"
}

case "$WHICH" in
  backend) run_backend ;;
  swift)   run_swift ;;
  all)     run_backend; run_swift ;;
  *) echo "usage: $0 [all|backend|swift]"; exit 2 ;;
esac

say "SUMMARY"
printf '  passed: %d   failed: %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && { printf '\033[32mALL CLEAR\033[0m\n'; exit 0; } \
                  || { printf '\033[31mFAILURES ABOVE\033[0m\n'; exit 1; }
