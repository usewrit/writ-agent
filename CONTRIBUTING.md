# Contributing to writ-agent

Thanks for your interest in contributing. This document covers the local dev
setup, how to run the checks CI runs, and what we expect from pull requests.

## Prerequisites

- **Rust** 1.88 or newer (see `rust-version` in `Cargo.toml`; CI enforces it, so it is a real floor, not an aspiration).
- **Network access on first build**: the vendored `playwright-rs` crate's
  `build.rs` fetches the Playwright Node.js driver (SHA-256 pinned) from the PyPI
  `playwright` wheel into Cargo's `OUT_DIR`, and also mirrors it into
  `~/.cache/playwright-rs-driver/` so it survives `cargo clean` and lockfile
  churn. You do **not** need Node.js, npm, or Python installed — the wheel is
  just a ZIP and the driver bundles its own `node` binary. Because the driver also
  lands in `target/`, any `target/` cache (e.g. `Swatinem/rust-cache` in CI)
  caches it too.
  - If the driver cannot be obtained the build **fails** with an actionable
    message. It will not produce a binary that cannot launch a browser.
  - Offline: point `PLAYWRIGHT_DRIVER_PATH` at an already-extracted driver
    directory (containing `node` and `package/cli.js`) and no network call is
    made. To use an internal mirror set `PLAYWRIGHT_DRIVER_URL` **and**
    `PLAYWRIGHT_DRIVER_SHA256` — a URL without a digest is rejected rather than
    downloaded unverified.
- **Chromium** is installed on first browser use via the bundled driver CLI; no
  separate browser install step is needed for a plain build.
- On Linux you need the usual build deps: `pkg-config` and `libssl-dev`.

## Building

The OSS self-host build (the one CI checks) is:

```sh
cargo check --no-default-features --features local,fleet,openai
cargo build --release --no-default-features --features local,fleet,openai --bin writ-agent-fleet
```

Note that a bare `cargo build` produces the managed **cloud** agent (`cloud` is
a default feature) — see the feature-flag section of the README before choosing
build flags.

## Running tests

```sh
cargo test --no-default-features --features local,fleet,openai
```

One integration test needs an extra test-only feature (it compiles a
deterministic verification key):

```sh
cargo test --features local,update-test-keys --test update_verify
```

## License and supply-chain checks

CI enforces `cargo-deny` (advisories, license allowlist, bans, sources) against
the committed `Cargo.lock`:

```sh
cargo install cargo-deny --locked
cargo deny check            # or: cargo deny check licenses|advisories|bans|sources
```

The policy lives in `deny.toml`. Any exception (ignored advisory, allowed
license, skipped duplicate) must carry an inline comment with the reason, an
owner, and an expiry date — entries without an expiry are not accepted.

Third-party license notices are generated with `cargo-about` (config in
`about.toml`, template in `about.hbs`):

```sh
cargo install cargo-about --locked --version 0.6.6
cargo fetch --locked        # `--offline` below resolves the whole graph from the local cache
cargo about generate --offline --all-features about.hbs
```

**If your local regeneration differs from the committed file by whitespace only, trust CI, not your
machine.** `cargo fetch` fills `registry/cache/` with `.crate` archives but never extracts them to
`registry/src/`, so cargo-about harvests some license texts differently on a cold runner than on a
machine that has built the tree. The committed file is kept matching the clean-room output, because
that is the environment the check actually runs in and it derives entirely from `Cargo.lock`.

The version pin is not optional. Different `cargo-about` releases render the notices differently,
so an unpinned install makes the CI check fail on a file nobody touched — and from 0.9 onwards the
binary sits behind a `cli` feature, so a plain `cargo install cargo-about` installs **nothing** and
merely warns. Bump the pin and regenerate the file in the same commit.

## Pull requests

- Open an issue or discussion first for anything larger than a straightforward
  fix, so we can agree on the approach before you invest time.
- Keep PRs focused: one logical change per PR.
- Make sure `cargo check`, `cargo test` (with the feature flags above),
  `cargo clippy --all-targets` (in BOTH feature configurations — they compile different halves of
  the crate) and `cargo deny check` pass locally. CI enforces all four.
- **Formatting is not gated.** This tree predates a rustfmt config, so `cargo fmt` would rewrite
  ~14k lines; `rustfmt.toml` pins the width the code was written at (100 cols) so your editor
  matches. If you want to normalize formatting, do it as one isolated commit that changes nothing
  else.
- Do not edit files under `vendor/` unless the change is specifically about the
  vendored driver shim — explain why in the PR description if so.
- New behavior that touches security posture (network destinations, key
  handling, browser flags) must be reflected in `docs/DISCLOSURES.md` and, if
  user-facing, `docs/CONFIGURATION.md`.
- Add a line to `CHANGELOG.md` under the unreleased section for user-visible
  changes.

By contributing you agree that your contributions are licensed under the
project license (AGPL-3.0-only).

## Reporting security issues

Never open a public issue for a vulnerability — use the private reporting flow
described in [`SECURITY.md`](./SECURITY.md).
