# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.6] - 2026-08-20

### Added

- **A connected model can work as one of your saved identities.** The MCP surface gained
  `writ_personas`, so a model can see which identities you have saved and name one when it scrapes,
  crawls or opens a browser. The identity's warm session is restored into the page before the first
  step runs, which is what lets a model read a page that only a signed-in user can see.
- **Data arrives as a preview and fills in when you look closer.** A single row of crawled markdown
  can run to tens of kilobytes, and all of it was being shipped just to draw a table. Long text cells
  now arrive cut to a preview and marked as cut, and the full record is fetched on demand when you
  expand, copy, export or send it — an export never contains a truncated value.

### Changed

- **Anonymous usage telemetry is now on by default.** It is counts and durations only — never page
  content, never URLs — and it goes to the coordinator this agent is linked to, over the link you
  already configured. An agent linked to your own self-hosted coordinator reports to your own server;
  an agent linked to nothing has nowhere to send and never tries. Turn it off with
  `writ telemetry off`, look at a day's report first with `writ telemetry preview`, or set
  `telemetry_opt_in = false`. An explicit `false` is always honored, so an install that had already
  opted out stays opted out.
- **An abandoned browser is reclaimed in minutes rather than never.** Only the CLI entry point ever
  started the session reaper, so in the desktop app nothing reclaimed recording sessions at all: a
  client that dropped without closing left its Chromium context alive until the process exited. The
  reaper now runs wherever the daemon does, and MCP-opened browsers get a much shorter window of
  their own — a model that has gone quiet for five minutes has been abandoned, while a person
  recording a workflow legitimately pauses to think, so the two no longer share a timeout.
- **Opening a workflow's data no longer costs its whole history.** Every data view parsed the full
  window of stored runs before it could show a single page. Reads are now served from a summary and
  only the rows on the page are loaded.

### Fixed

- **Crawling a signed-in page returned a list of empty headings.** On an account screen, a dashboard
  or a settings panel the form *is* the content, but a field's value is an attribute rather than
  text, so the article extractor dropped it — on a real profile page it kept 53 of 591 visible words.
  When an extracted body comes back starved while the page clearly has text, the visible form fields
  are now recovered as `label: value` lines. Password-type fields are skipped entirely — neither
  their value nor their presence is emitted — and every value is length-capped.
- **A restored identity kept its cookies but arrived with a fresh browser fingerprint.** A saved
  session was replayed under a newly minted user agent, so a site that binds its session to the
  browser signed the identity straight back out. The saved fingerprint now travels with the session
  everywhere it is restored, and an identity's saved headers are replayed too — scoped to the domain
  they were captured from, so they never leak to a third-party host.
- **Optimizing a workflow captured the sign-in page but not the sign-in.** The capture answered for
  the page it was already on, so the submit that actually authenticates was missed and the resulting
  API workflow signed in to nothing. Optimization now waits on requests still in flight, and replays
  from cold when the workflow signs in for real.

### Security

- Updated `h2` past a denial-of-service advisory affecting HTTP/2 request handling
  ([GHSA-q83h-524g-xf6h](https://github.com/hyperium/hyper/security/advisories/GHSA-q83h-524g-xf6h)).

## [1.0.5] - 2026-08-15

### Added

- **A persona can sign itself in.** A persona's warm session could previously only arrive by capture
  from something that had already signed in — and locally that capture never happened: a successful
  run harvested its session under the workflow, never onto the persona. So a persona created from
  credentials alone never had a session, and every authenticated local crawl using it was refused
  with no route out of the error. A persona can now name the workflow that performs its login
  (migration `0025`); running that workflow with the persona resolved folds in its credentials and
  2FA, and the harvested session is written back onto the persona. Sign-in happens on demand and
  automatically when a crawl finds the session stale, and the last failure is recorded so the reason
  is visible without digging through run history. Deleting the login workflow leaves the identity
  intact — it only leaves the persona unable to re-login until another workflow is attached.
- **Concurrent sign-in attempts collapse to one.** When several callers want the same persona signed
  in at once — a crawl seeder retrying, someone pressing "sign in" repeatedly — one performs the
  login and the rest wait on its result. N simultaneous logins against a single account is the
  pattern that trips a site's abuse defences and gets the account locked.
- **Documents found while crawling are stored, not just parsed.** A discovered document's raw bytes
  are captured as a tenant file alongside the extracted text, deduplicated by content so an unchanged
  document is linked rather than re-uploaded. Capture is additive by design: with no artifact
  endpoint available, no token, or any error on the way, the page still succeeds — the extracted text
  is the crawl's product and must never fail because the original could not be stored.

## [1.0.4] - 2026-08-13

### Fixed

- **The desktop shell could not stop the daemon on Windows.** Windows has no `SIGTERM`, so "Quit"
  reached for `taskkill /PID <pid> /T` — which asks by posting to the target's console or windows,
  and a daemon spawned as a sidecar by a GUI-subsystem shell has neither. Quit therefore exited the
  app and left `writ-agentd` running; `/F` would only have traded that for a `TerminateProcess`,
  leaving `runtime.json` and the singleton lock behind for the next start to collide with. A new
  `POST /v1/shutdown` (loopback + bearer gated) enters the same graceful path `Ctrl-C` and `SIGTERM`
  already used: drain the scheduler, stop the supervisors, release the lock, remove the runtime file.
- **Chromium could never finish installing on ARM64 Windows.** "Which platforms can we download a
  build for" and "which platforms do we hold a verification pin for" had drifted into two
  independent `cfg!` ladders. The download succeeded and the integrity gate then refused it with
  "no Chromium pin for this platform" — and because that gate fails closed, onboarding could never
  complete, even though the pin was in the file all along. Both questions are now answered by one
  function, so a platform cannot be half-added again.
- **Home-directory lookup failed on Windows.** `HOME` is not set there, so every home-derived
  driver candidate resolved to `None` — silently, since each caller reads `None` as "not present"
  rather than "could not look". `USERPROFILE`, then `HOMEDRIVE` + `HOMEPATH`, are now consulted.
  When nothing resolves, the daemon logs the executable path, the environment overrides, the
  resolved home and every candidate it tried, so a shipped build can answer "where did you look?"
  instead of surfacing an opaque driver timeout.

### Changed

- **Opening an encrypted database is fast again.** A full 64-character hex key is now passed to
  SQLCipher as a raw key rather than a passphrase, skipping per-connection key derivation. A
  database written by an older build under the passphrase form is migrated in place, with its data
  intact — not quarantined.
- Every OS-keyring secret kept outside the encrypted database — vault root, cloud token, per-agent
  channel key, relay credential — now opens its entry through one seam. Behaviour is unchanged, and
  no environment variable or runtime switch can divert a real secret away from the OS keyring.

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
