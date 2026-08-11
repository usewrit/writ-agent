# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2026-08-11

### Fixed

- **A file chosen at run time is no longer ignored.** An upload step resolves its file from two
  places: the slot a caller bound for *this* run (the run form's picker, a `files` map over REST or
  MCP, a buyer-bound recipe slot) and the file pinned on the step itself. The pin was resolved
  first, so picking a different file in the run form silently uploaded the old one. Slot now wins;
  with nothing bound to the slot the pinned file is still used, so an untouched run behaves exactly
  as before. This matches the precedence the replay engine already documented.
- **An on-device AI task's live preview is no longer blank.** Such a task runs its whole loop
  against its own browser context and was never registered as a browsing session, so opening the
  viewer for it matched nothing and returned silently — a permanently black preview, while the
  equivalent interactive path worked. The task now publishes its page under the session id a viewer
  actually opens, after navigation succeeds so a spectator never attaches to a dead page, and
  withdraws it on the single cleanup exit.

### Changed

- **Every upload step is addressable over MCP, not just those declaring a named slot.** A recorded
  step usually just pins a file rather than declaring an abstract slot, which left no way to run the
  workflow against a different file without editing it. Each such step now exposes a `step:<id>`
  key — its own step id rather than an ordinal, so reordering or disabling a step cannot shift it.
  Every key is optional and a pinned step still runs untouched; steps that already have a file stay
  out of the elicitation list, so nothing prompts for something it does not need.

## [1.0.1] - 2026-08-10

### Added

- **The agent downloads Chromium itself, with no interpreter on the machine.** The previous path
  shelled out to `patchright` / `playwright` / `npx`, every one of which needs Python or Node
  already installed — fine on a developer box, useless on a clean host, where the install simply
  failed and left an agent that could not open a browser. `browser::chromium_download` replaces it
  with plain HTTPS plus an unzip: no interpreter, no package manager, no `PATH` assumptions.
- **A persona now runs from one consistent machine.** A residential proxy buys a clean IP; it does
  not answer the next question a detector asks — *is this the same device as last time, and is that
  device internally consistent?* A freshly randomised context fails both: the hardware signature
  changed on every run, so an aged, cookie-bearing session kept reappearing on a "new computer",
  and the pieces contradicted each other (a Windows user-agent alongside a `MacIntel` platform).
  `browser::device_identity` derives one coherent desktop device deterministically from the persona
  id, so the same persona reconstructs the same machine on every run and on every agent, with no
  state to share between them.
- **Locale, timezone and `Accept-Language` follow the egress exit country.** `browser::geo` derives
  the triple per session from where the connection actually exits, because anti-bot systems compare
  those against the GeoIP of the connecting address — a US timezone on a Canadian exit is a
  contradiction no real user produces. Unknown countries fall back to a neutral, self-consistent
  default rather than guessing.
- `Fingerprint` gains `device` and `accept_language`. Both default when absent, so fingerprints
  banked before these fields existed still load unchanged.
- **Uploads are recordable.** A page's file chooser opens an operating-system dialog, and the
  recorded browser runs on an agent — so the person recording could never answer it, and the chooser
  could only be dismissed empty. Everything downstream of the upload (submit, preview, progress, the
  success screen) was therefore unrecordable. The recorder now turns the dialog into a round-trip:
  it emits an `upload_prompt`, the client answers with a stored file, and the bytes are handed to
  the chooser so the page performs a real upload exactly as it would for a person. The client
  supplies the URL because it is the only side that can authenticate for the bytes. Skipping, a
  timeout or an unreachable file all fall back to dismiss-empty, so a recording is never blocked by
  the prompt.
- A `windows-aarch64` digest for a new Chromium revision in the pinned download table. Additive
  only — no existing pin changed.

### Changed

- **The browser is now open-source Chromium, not "Google Chrome for Testing".** Chrome for Testing
  is what the Playwright tooling installs; it is Google-copyrighted and distributed under the Chrome
  Terms of Service. The agent now fetches BSD-3-Clause Chromium from the Chromium project's own
  snapshot bucket, at a revision pinned to a stable release, so the user obtains the browser from
  Google directly rather than receiving a copy from us. Attribution updated in
  [`BUNDLED_BINARIES.md`](./BUNDLED_BINARIES.md).

### Security

- **The first-run browser download is integrity-checked and fails closed.** The launchable binary is
  hashed and compared against a SHA-256 pin compiled into the agent, per revision and per platform;
  a mismatch, a missing pin, or an unreadable pin table refuses the install rather than completing
  it. The shipped pin table previously held placeholder zeros — every entry is now a real digest.
  Archive entries with unsafe paths are skipped during extraction.

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
  driver gets used" and [`docs/DISCLOSURES.md`](./docs/DISCLOSURES.md) §4 — the patchright install is
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
- **Saved crawls** — a crawl configuration now has a stable handle, so it can be called like a
  workflow. A `crawl_jobs` row is one *run*: its settings lived on the row and its id died with the
  run, so a crawl could not be exposed as a callable API (the id changed on every re-crawl) and
  "re-crawl with the same settings" meant refilling a form. `crawl_definitions` (migration `0024`)
  owns the saved settings as a single JSON blob in the same shape the `POST /v1/crawl` body takes —
  so a new crawl option cannot silently fall out of a hand-maintained column mirror — plus a slug for
  the callable endpoint. `crawl_jobs.definition_id` points each run back at the config that launched
  it, making runs the definition's history. The migration is additive: the new column is `NULL` for
  every pre-existing ad-hoc crawl and needs no backfill. New routes under
  `/v1/crawl/definitions/…` (create, list, read, run, fetch data).
- `max_age` is advertised on **every** workflow's derived MCP tool, not just `writ_run_workflow`, so
  an agent can discover the freshness control where it is actually calling. A workflow that genuinely
  declares an input named `max_age` keeps its own meaning — the control never shadows a real
  placeholder.
- The crawl's HTTP lane advertises the same `Accept-Encoding` a real Chrome does. `reqwest` gains the
  `brotli`, `deflate` and `zstd` features so the header it derives and the bodies it can decode can
  never drift apart — hand-writing Chrome's list without them would return `br`/`zstd` bodies the
  lane cannot read, and the crawl would extract binary garbage instead of text.
- Supply-chain gate: `cargo deny` (advisories, licenses, bans, sources) on every
  PR and weekly on a schedule, and `THIRD_PARTY_NOTICES.md` generated from the
  locked dependency graph with `cargo-about` (CI fails if it drifts).

### Security

- **Cloud API-key issuance requires the `manage` scope.** `POST /v1/cloud/reflect/api-keys` mints an
  account key and returns its one-time secret, and `.../{id}/delete` revokes one, but neither path
  was listed in `is_device_management_path` — so both resolved to `Scope::Admin`, the scope an
  ordinary "create a workflow" key carries. The equivalent local route (`/v1/keys`) already required
  `Manage` on the reasoning that "a key that can mint keys can escalate itself arbitrarily"; the
  cloud variant is strictly broader, because the credential it returns is scoped to the account
  rather than this device, and `admin` deliberately does not imply `manage`. Now prefix-matched so
  future mutations under that path are fail-closed; the GET list/catalog remain `read`, as they
  carry metadata only.
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
