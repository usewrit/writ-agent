# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-28

### Added

- Initial open-source release of **writ-agent**, the self-hostable
  browser-automation worker for Writ.
- `writ-agent-fleet`: the self-host fleet worker binary. Connects outbound to a
  self-host coordinator
  ([usewrit/writ](https://github.com/usewrit/writ)), receives
  deployed workflows, and executes them entirely on the local machine.
- SQLCipher-encrypted local store and vault; key custody via an OS keyring
  (opt-in) or a `0600` key file.
- Coordinator WebSocket link with TLS verification and a plaintext-to-remote
  refusal (override only via explicit `WRIT_FLEET_ALLOW_INSECURE` opt-in).
- Crawl-shard execution: the worker runs crawl shards dispatched by the
  coordinator.
- Monitor execution: the worker runs the change/uptime targets the coordinator
  assigns to it, in `content`, `uptime` and `playwright` check modes.
- AI-assisted browsing against **your own** provider key (OpenAI, Anthropic,
  Gemini, any OpenAI-compatible endpoint, or a local Ollama). Prompts and page
  content go directly from your host to that provider.
- Loopback-only status endpoint: set `WRIT_FLEET_STATUS_PORT` to expose
  `GET /healthz` (JSON `{status, connected, uptime_s, last_task_at, version}`,
  `503` while disconnected) for Docker `HEALTHCHECK` / systemd watchdogs.
- Desktop daemon (`writ-agentd`) and local control CLI (`writ`) for the local
  desktop build.
- Release artifacts for five platforms (Linux x86_64/aarch64, macOS
  arm64/x86_64, Windows x86_64), each with a SHA-256 sidecar, plus a multi-arch
  container image at `ghcr.io/usewrit/writ-agent`.
- Relocatable Playwright driver resolution: the worker now looks for a driver at
  `<directory of the executable>/playwright-driver` and `$WRIT_HOME/playwright-driver`
  before falling back to the path baked in at compile time. The release archives
  and the container image ship the driver in exactly that layout, so a
  downloaded worker launches browsers with no configuration. Without this a
  binary built on one machine and run on another starts, connects and reports
  healthy, then fails every run at browser launch with `ServerNotFound` — the
  compile-time path is an absolute path on the *build* machine. See
  [`docs/CONFIGURATION.md`](./docs/CONFIGURATION.md) §"Which Playwright driver
  gets used".
- The container image ships **patchright's stealth driver** alongside the vanilla one, and
  `find_patchright_driver` looks for `patchright-driver/` next to the executable (and under
  `WRIT_HOME`) before falling back to probing for a Python that can `import patchright`. Every
  previous probe needed an interpreter, which neither the image nor a release archive ships — so
  those deployments silently ran **vanilla** (detectable: `Runtime.enable` on, plus the console
  event flood that inflates per-action latency) with only a warning line to say so. Both drivers are
  kept as separate directories so the stealth one is chosen on merit and `WRIT_DISABLE_PATCHRIGHT=1`
  still falls back cleanly. See [`docs/CONFIGURATION.md`](./docs/CONFIGURATION.md) §"Which Playwright
  driver gets used" and [`docs/DISCLOSURES.md`](./docs/DISCLOSURES.md) §5 — the patchright install is
  version-pinned to the 1.60 line but, unlike the Playwright wheel, **not digest-pinned**.
- **The recorder no longer wedges on a navigation that races a user action.** The session table is
  a `DashMap`, whose guards are synchronous `RwLock`s: calling `sessions.get()` from an async task
  does not yield, it parks the tokio worker. An action handler held a write guard across its awaits
  while the page navigated; the spawned `frameNavigated` task then blocked a worker waiting for that
  guard, and with the workers parked nothing was left to pump the Playwright driver pipe — which is
  what the action was awaiting. Circular wait, permanently frozen, on a small VPS or a CPU-limited
  container where the worker count is 1 or 2. Earlier mitigations addressed the lock *holder*; the
  new `recorder::session_lock` addresses the *waiter*, acquiring with `try_get` and yielding on
  contention so the worker stays free.
- **SSRF hostname verdicts are cached and time-bounded.** Resolution results are memoised for 60s —
  short enough that a DNS rebind is caught on the next page load — and DNS lookups now have explicit
  timeouts: subresource checks fail **open** after 2s so a slow resolver can never hold the browser's
  route handler open, while navigation targets get 5s and fail **closed**. The guard screens
  obviously-internal targets; it has never been able to pin the address the browser ultimately
  connects to, since the browser resolves independently.
- The crawl's HTTP lane advertises the same `Accept-Encoding` a real Chrome does. `reqwest` gains the
  `brotli`, `deflate` and `zstd` features so the header it derives and the bodies it can decode can
  never drift apart — hand-writing Chrome's list without them would return `br`/`zstd` bodies the
  lane cannot read, and the crawl would extract binary garbage instead of text.
- Supply-chain gate: `cargo deny` (advisories, licenses, bans, sources) on every
  PR and weekly on a schedule, and `THIRD_PARTY_NOTICES.md` generated from the
  locked dependency graph with `cargo-about` (CI fails if it drifts).

### Security

- Pinned `quinn-proto` past [RUSTSEC-2026-0185] (remote memory exhaustion). The
  crate is not reachable from any feature set this repository builds — `reqwest`
  lists it behind its optional HTTP/3 support, which is off — but a lockfile
  entry a scanner can see is a lockfile entry worth fixing.
- Documented the one remaining flat-lockfile advisory,
  [RUSTSEC-2023-0071] (`rsa`, reached only through the MySQL driver of `sqlx`,
  which is not enabled), in [`.cargo/audit.toml`](./.cargo/audit.toml) with a
  verification recipe and an expiry date.

[RUSTSEC-2026-0185]: https://rustsec.org/advisories/RUSTSEC-2026-0185
[RUSTSEC-2023-0071]: https://rustsec.org/advisories/RUSTSEC-2023-0071
