# Configuration reference

Everything that configures the agent: environment variables and the on-disk
`~/.writ/config.toml` (TOML — the only config-file format the agent reads).
Precedence, where it matters, is: **environment variable → `config.toml` value →
built-in default**.

Data lives under `~/.writ` by default (override with `WRIT_HOME`). Any local API
binds **`127.0.0.1`** — reaching it from the LAN requires an explicit opt-in (see
`WRIT_NETWORK_EXPOSE` below).

---

## Environment variables

### Fleet worker (`writ-agent-fleet`, self-host)

The self-host fleet worker is configured **entirely via environment variables**
(the config-writing CLI is absent from the fleet build; the worker still reads
`config.toml` for the engine resource-governor ceilings, see below). It connects
*out* to your self-host coordinator
([usewrit/writ](https://github.com/usewrit/writ)): it POSTs
`<coordinator>/api/recorder/connect` with the fleet token as Bearer, then dials
the WebSocket the coordinator hands back.

| Variable | Required | Effect |
|----------|----------|--------|
| `WRIT_SERVICE_TOKEN` | **yes** | The fleet token for the coordinator link, minted in the coordinator UI (**Fleet → "Connect a new agent"**). Sent as the connect Bearer. |
| `WRIT_COORDINATOR_URL` | **yes** | The coordinator HTTP(S) **base** URL (e.g. `https://coordinator.example.com`) — *not* the WS URL. `SAAS_URL` is accepted as a legacy alias. |
| `WRIT_HOME` | no (default `~/.writ`) | Data directory: the SQLCipher-encrypted `writ.db` plus the `0600 vault.key` file root when the OS keyring is off. `WRIT_VAULT_ROOT` is an alias for pointing a headless deployment at a mounted volume. **One process per directory** — see the singleton lock below. |
| `WRIT_USE_KEYRING` | no (default off) | `1`/`true` roots the vault key in the OS keyring instead of the `vault.key` file. Off by default so a container/service never blocks on a keychain prompt. |
| `WRIT_FLEET_ALLOW_INSECURE` | no (default off) | `1`/`true` allows a plaintext `http://`/`ws://` coordinator that is not loopback. Only for trusted private networks — the worker otherwise refuses to send its token in cleartext. |
| `WRIT_AI_KEYS_CONFIGURED` | no (default off) | `1`/`true` advertises BYO-AI capability to the coordinator. |
| `WRIT_RETENTION_DAYS` | no (default `90`) | Data-retention window in days; `0` keeps everything. The fleet worker runs neither the desktop scheduler nor the local HTTP API, so it drives its **own** periodic maintenance from this value — see "Fleet worker data maintenance" below. |
| `WRIT_FLEET_DRAIN_TIMEOUT_S` | no (default `30`, max `600`) | Bounded **graceful-drain** window on `SIGTERM`/Ctrl-C. The worker waits up to this long for in-flight runs to finish (so each one's `task_result` still reaches the coordinator), then shuts the browser down explicitly and exits `0`. `0` disables the drain. Must be **less than** the supervisor's stop grace period (`docker stop -t`, Compose `stop_grace_period`, systemd `TimeoutStopSec`, Kubernetes `terminationGracePeriodSeconds`) or the drain is `SIGKILL`ed part-way. |
| `WRIT_FLEET_STATUS_PORT` | no (off unless set) | Exposes a **loopback-only** (`127.0.0.1`) status endpoint on the given port: `GET /healthz` returns JSON `{status, connected, draining, db_ok, auth_rejected, auth_failures, auth_error, uptime_s, last_task_at, tracked_tasks, infra_failure_streak, infra_failure_threshold, version}`. HTTP `200` only when **every** check passes; otherwise `503` with `status` naming the first failing one: `draining`, `auth_rejected`, `disconnected`, `db_unavailable` (the store failed a `SELECT 1` probe), or `task_failures` (consecutive infrastructure-category run failures crossed the threshold). Use it with a Docker `HEALTHCHECK` or systemd watchdog. |

The fleet worker always runs the browser **headless** and honors the
resource-governor settings from `config.toml` / the `WRIT_MAX_*` variables below.

**Singleton lock.** On startup the worker takes a pidfile lock at
`$WRIT_HOME/writ.lock` and **refuses to start** if another live Writ process (a
second worker, or another Writ process) already owns that directory. Two processes
over one home each open their own connection pool against the same SQLCipher
file, and each independently runs the managed boot policy that *quarantines* a
database it cannot read — so one worker can rename the other's live `writ.db`
aside and start fresh. Give every worker its own directory (a separate Docker
volume per container, or `WRIT_HOME=~/.writ-worker2` per systemd unit). A
lockfile left by a `kill -9` is reclaimed automatically on the next start once
the recorded pid is confirmed dead.

**Fleet worker data maintenance.** Because there is no scheduler and no
`POST /v1/data-admin` in this build, the worker runs its own maintenance loop:
hourly it caps any oversized log file and runs `PRAGMA wal_checkpoint(TRUNCATE)`
(returning the `writ.db-wal` high-water mark to the filesystem), and daily it
runs the full retention purge for `WRIT_RETENTION_DAYS` — run history, change
history, uptime samples, AI replay keyframes, captured workflow-output blobs, and
expired `logs/` files (`crash-*.json`, `*.log`/`*.err`/`*.out`). The first pass
runs immediately at startup, so a worker restarted because its volume filled
reclaims space right away. The log size cap is a disk-safety valve and applies
even with `WRIT_RETENTION_DAYS=0`; `VACUUM` is deliberately *not* run (it needs a
transient copy of the whole database plus an exclusive lock).

### Core / paths

| Variable | Default | Effect |
|----------|---------|--------|
| `WRIT_HOME` | `~/.writ` | Root data directory (DB, vault key, file stores, config, runtime.json). |
| `WRIT_PORT` | `8131` | Local API port. Bind host is loopback unless LAN exposure is enabled. |
| `WRIT_PROFILE` | `local` | Active profile / keyring account key. Each profile has its own data home. A blank value folds to `local`. |
| `WRIT_LANGUAGE` | (UI-set) | Default UI language (BCP-47-ish short tag) reflected to the frontend. |
| `WRIT_ONBOARDING_COMPLETED` | `false` | Marks onboarding done (normally written by the app). |

### Vault / keyring

| Variable | Default | Effect |
|----------|---------|--------|
| `WRIT_USE_KEYRING` | `false` | Store the vault root in the OS keyring instead of plaintext `~/.writ/vault.key`. **Off by default** — see SECURITY.md. |

### Network exposure

| Variable | Default | Effect |
|----------|---------|--------|
| `WRIT_NETWORK_EXPOSE` | `false` | Bind the API to `0.0.0.0` (LAN-reachable). Disabling via env is always honored. **Enabling** via env in a release build additionally requires `WRIT_ALLOW_ENV_EXPOSE` (below). |
| `WRIT_ALLOW_ENV_EXPOSE` | unset | Acknowledges the risk of enabling LAN exposure via env in a release build. Without it, `WRIT_NETWORK_EXPOSE=1` is ignored (stays loopback) so a stray/injected env var can't silently expose the API. |

### Browser runtime

| Variable | Default | Effect |
|----------|---------|--------|
| `WRIT_HEADLESS` | `true` | Global default headless mode for the warm browser. `false` shows a visible window. Per-run overrides still apply. Boot-fixed. |
| `WRIT_DISABLE_PATCHRIGHT` | unset | Force the bundled **vanilla** Playwright driver (no stealth) instead of patchright. For A/B testing. |
| `WRIT_PATCHRIGHT_DRIVER` | (auto) | Operator override pointing at an existing patchright `driver` directory (enables stealth without a separate install). |
| `PLAYWRIGHT_DRIVER_PATH` | unset | **Runtime override, highest priority.** A driver directory (`node` + `package/cli.js`) to drive instead of anything resolved below. Also a build-time variable — see the build section. |
| `PLAYWRIGHT_NODE_EXE` + `PLAYWRIGHT_CLI_JS` | unset | Runtime override naming the two files directly. Ranks below `PLAYWRIGHT_DRIVER_PATH`; setting either suppresses the automatic resolution entirely. |

#### Which Playwright driver gets used

Resolved once at process start (`browser::manager::init_driver_env`), in this order:

1. `PLAYWRIGHT_DRIVER_PATH`, or `PLAYWRIGHT_NODE_EXE` + `PLAYWRIGHT_CLI_JS` — an operator override
   wins outright and nothing below runs.
2. **patchright's stealth driver** (unless `WRIT_DISABLE_PATCHRIGHT=1`), looked up as
   `WRIT_PATCHRIGHT_DRIVER` → `<directory of the executable>/patchright-driver` →
   `$WRIT_HOME/patchright-driver` → a Python that can `import patchright`. Preferred because it
   suppresses `Runtime.enable`, the biggest anti-bot signature.
3. **The vanilla driver shipped alongside the binary** — `<directory of the executable>/playwright-driver`,
   then `$WRIT_HOME/playwright-driver`.
4. The **compile-time bundled** driver baked in by `vendor/playwright-rs/build.rs`.

The two sibling lookups are why a downloaded release or the container image needs no configuration:
step 4 is an absolute path on the machine that *compiled* the binary, so it only resolves for a
build you made yourself and did not move. Keep `playwright-driver/` (and, in the image,
`patchright-driver/`) next to `writ-agent-fleet` and everything resolves on its own.

The sibling lookup in step 2 matters for exactly the deployments that need stealth most. Every
other patchright probe requires an interpreter that can `import patchright`, and neither the
container image nor a release archive ships Python — so before it existed those deployments silently
ran **vanilla** (detectable, `Runtime.enable` on) with only a warning line to say so. The container
image now carries both drivers side by side, so the stealth one is chosen on merit and
`WRIT_DISABLE_PATCHRIGHT=1` still falls back cleanly to the vanilla one.

A binary with none of the four available starts and connects normally, then fails at the first
browser launch — check the startup log line naming the driver it chose.

#### Dangerous browser-security toggles (all default `false` = secure)

These disable real OS/browser protections. Leave off unless you fully understand
the exposure. Boot-fixed (a change applies on restart). See DISCLOSURES §"Browser
security-weakening toggles".

| Variable | Default | Effect |
|----------|---------|--------|
| `WRIT_BROWSER_DISABLE_SANDBOX` | `false` | Launches Chromium with `--no-sandbox`. |
| `WRIT_BROWSER_IGNORE_CERT_ERRORS` | `false` | Launches with `--ignore-certificate-errors` (accepts invalid TLS). |
| `WRIT_BROWSER_DISABLE_WEB_SECURITY` | `false` | Launches with `--disable-web-security` (disables same-origin policy). |
| `WRIT_BROWSER_USE_LOCAL_CHROME` | `false` | Seeds the browser baseline from your **real** local Chrome profile — copies live cookies/storage to disk (`$WRIT_HOME/.browser_profile`, 0700/0600). See DISCLOSURES §"Local Chrome profile copy". |

### Resource governor

| Variable | Default | Effect |
|----------|---------|--------|
| `WRIT_MAX_CONCURRENT_RUNS` | `4` | Max concurrent workflow runs (ceiling 64). |
| `WRIT_MAX_BACKGROUND_RUNS` | `2` | Max background runs (clamped to `1..=max_concurrent_runs`). |

> **Fleet throughput is governed by these values, not by your CPU count.**
>
> A fleet worker advertises its capacity to the coordinator as `max_background_runs` (default **2**).
> It used to advertise `min(cpu_cores, RAM_GB / 1.3)` — a number nothing enforced, so a 16-core box
> claimed 16, the coordinator scheduled 16, and 14 of them failed instantly against the background
> ceiling of 2 while crawl shards bypassed the ceiling entirely and could OOM the host.
>
> So: **to give a worker more throughput, raise `WRIT_MAX_CONCURRENT_RUNS` and
> `WRIT_MAX_BACKGROUND_RUNS`** (or the `config.toml` equivalents). `WRIT_MAX_SESSIONS` and the
> coordinator's own capacity setting can now only *lower* the advertised number, never raise it above
> what the governor will actually admit — the point being that the number the coordinator schedules
> against is the number that can really run.
>
> Live browser contexts are separately bounded at `2 × max_concurrent_runs` (floor 4), because
> recording, monitoring, streaming and the concierge share the same browser without taking governor
> permits.
| `WRIT_RSS_SOFT_WATERMARK_MB` | `0` | Soft RSS watermark (MB); when resident memory exceeds it the agent sheds new work. `0` disables memory-based shedding. |

### Retention

| Variable | Default | Effect |
|----------|---------|--------|
| `WRIT_RETENTION_DAYS` | `90` | Days to keep runs/changes/uptime checks/output artifacts/AI replay keyframes, and expired `logs/` files (`crash-*.json`, `*.log`). `0` disables the purge (keep everything) — except the log **size** cap, which is a disk-safety valve and always applies. See DISCLOSURES §"Retention". |

### Streaming / monitors

| Variable | Default | Effect |
|----------|---------|--------|
| `WRIT_STREAMING_TURN_TIMEOUT_SECS` | `120` | Per-turn watchdog for streaming sessions. |
| `WRIT_HTML_FLOOR_MS` | (see DISCLOSURES) | Raise the HTML/HTTP monitor check floor. Absolute minimum floors are raisable, never lowerable. |
| `WRIT_JS_FLOOR_MS` | (see DISCLOSURES) | Raise the browser (playwright) monitor check floor. |

### Telemetry (default no-op)

| Variable | Default | Effect |
|----------|---------|--------|
| `WRIT_TELEMETRY` | `false` | Opt in to anonymous telemetry. **No-op unless a DSN is also configured.** |
| `WRIT_TELEMETRY_DSN` | unset | The telemetry/crash-report endpoint. There is **no built-in DSN**, so with this unset telemetry is genuinely a no-op even if `WRIT_TELEMETRY` is on. |

### AI provider key fallbacks

If an AI provider key is not set in the vault, the agent falls back to these
environment variables. Prompts + page content go directly to *your* provider on
*your* key (see DISCLOSURES §"AI provider data flow").

| Variable | Provider |
|----------|----------|
| `OPENAI_API_KEY` | OpenAI |
| `ANTHROPIC_API_KEY` | Anthropic |
| `GEMINI_API_KEY` / `GOOGLE_API_KEY` | Google Gemini |

### Development-only

The `RECORDER_*` variables drive an optional local recorder server that is
**disabled by default** and starts only behind an explicit opt-in. They are
documented so their existence is not a surprise; a normal deployment sets none of
them.

| Variable | Default | Effect |
|----------|---------|--------|
| `RECORDER_ENABLE_LOCAL_SERVER` | unset | Must be `1` for that server to start at all; without it, it refuses to run. |
| `RECORDER_AUTH_BYPASS` | unset | **Dev only.** `1` disables WebSocket authentication entirely. Never set outside local development. |
| `RECORDER_PORT` / `RECORDER_HOST` / `RECORDER_HEADLESS` / `RECORDER_MAX_SESSIONS` / `RECORDER_SELF_URL` / `RECORDER_LOG_FILE` / `RECORDER_AUTH_SECRET` / `RECORDER_AGENT_ID` | — | Host/port and session knobs for that server. |
| `RECORDER_DISABLE_SANDBOX` / `RECORDER_IGNORE_CERT_ERRORS` / `RECORDER_DISABLE_WEB_SECURITY` / `RECORDER_USE_LOCAL_CHROME` | `false` | Equivalents of the dangerous `WRIT_BROWSER_*` toggles above, for that path. |

### Build-time driver overrides

Only relevant when you build from source; see [`CONTRIBUTING.md`](../CONTRIBUTING.md).

| Variable | Effect |
|----------|--------|
| `PLAYWRIGHT_DRIVER_PATH` | Use an already-extracted driver directory (must contain `node` + `package/cli.js`). Checked before any network access and before any cache — the offline/air-gapped path. Also a runtime override; see "Which Playwright driver gets used". |
| `PLAYWRIGHT_DRIVER_URL` | Fetch the driver archive from a mirror instead of PyPI. Requires `PLAYWRIGHT_DRIVER_SHA256`; a URL alone is a hard error. |
| `PLAYWRIGHT_DRIVER_SHA256` | Expected SHA-256 of the driver archive, overriding the pinned digest. |

---

## `config.toml`

The on-disk config lives at `~/.writ/config.toml` (schema_version = 1). Every field
is optional; a sparse or old file loads forward. Sections:

```toml
schema_version = 1

[server]
port = 8131            # WRIT_PORT

[app]
language = "en"        # WRIT_LANGUAGE
telemetry_opt_in = false   # WRIT_TELEMETRY
retention_days = 90        # WRIT_RETENTION_DAYS
onboarding_completed = false

[engine]
max_concurrent_runs = 4        # WRIT_MAX_CONCURRENT_RUNS
max_background_runs = 2        # WRIT_MAX_BACKGROUND_RUNS
rss_soft_watermark_mb = 0      # WRIT_RSS_SOFT_WATERMARK_MB

[browser]
headless = true                       # WRIT_HEADLESS
disable_sandbox = false               # WRIT_BROWSER_DISABLE_SANDBOX (DANGEROUS)
ignore_certificate_errors = false     # WRIT_BROWSER_IGNORE_CERT_ERRORS (DANGEROUS)
disable_web_security = false          # WRIT_BROWSER_DISABLE_WEB_SECURITY (DANGEROUS)
use_local_chrome = false              # WRIT_BROWSER_USE_LOCAL_CHROME

[monitors]
# Monitor scheduler safety floors (raisable, not lowerable). See docs/DISCLOSURES.md.

[ai]
# AI provider config (keys are vault-sealed, not stored here in plaintext).

[security]
use_keyring = false    # WRIT_USE_KEYRING — see SECURITY.md
```

> **Note:** the `[app]` section was historically written with string values
> (e.g. `onboarding_completed = "true"`). The loader tolerates lenient booleans
> and heals such files, but new writes use proper TOML types.
