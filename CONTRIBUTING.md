# Contributing to Atlas

Thanks for your interest in contributing.

## Contributor License Agreement (CLA)

Atlas is **dual-licensed**: free and open under **AGPL-3.0**, with **commercial licenses** available
from Clockwork Tree Inc. To keep that possible for the *whole* codebase — including community
contributions — **all contributors must agree to our Contributor License Agreement** before their
contributions can be merged. See [`CLA.md`](CLA.md).

In short: you grant Clockwork Tree Inc. a broad license to your contribution (including the right to
relicense and commercialize it), **while you keep ownership of your own work**. It's the standard
Apache ICLA, unmodified except for the recipient's name.

> A CLA-signing check will be enabled on pull requests; until then, opening a PR is taken as your
> agreement to the terms in `CLA.md`.

## How to contribute

- **Discuss first** for anything non-trivial — open an issue before a large PR.
- **Python is the reference-of-record.** Add or adjust the Python implementation and its tests (and
  known-answer parity vectors) first, then mirror the change into the Swift `AtlasCore`.
- **Tests must pass.** Run `pytest` in `backend/` and `swift test` in `ios/AtlasCore/`; CI runs both
  on every push and must be green.
- **Respect the invariants** — proofs-not-data, presence-gated keys, no stored biometric templates,
  liveness-is-not-identity. Don't weaken these to make a feature easier.

## Security

Please report vulnerabilities **privately** — see [`SECURITY.md`](SECURITY.md). Do **not** open a
public issue or pull request for a security bug.
