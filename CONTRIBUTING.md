# Contributing to ProxSep

Thanks for contributing.

## Before you start

ProxSep touches Windows networking, proxy protocols, process attribution, and an experimental WFP driver. Changes should be small enough to review and should clearly separate user-mode behavior from kernel-mode behavior.

For large features, open an issue first and describe the intended behavior, affected crates, and compatibility impact.

## Development checks

Run these before submitting a pull request:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check --workspace --all-targets
cargo test --workspace
```

If you modify the driver:

```powershell
.\scripts\build-driver.ps1
```

A successful driver build does not imply that installation, signing, or deployment is safe.

## Pull requests

Prefer one logical change per pull request.

A good pull request should include:

- What problem it solves.
- Which crate(s) or driver components are affected.
- How the behavior was tested.
- Any compatibility or security implications.
- Tests for new rule/protocol behavior where practical.

Avoid unrelated formatting churn.

## Compatibility work

Do not submit proprietary source code, extracted third-party assets, icons, branding, credentials, or confidential material.

Compatibility implementations must be independently written from public documentation, public formats, or independently observed behavior.

## License

By contributing to this repository, you agree that your contribution is licensed under GPL-3.0-or-later.
