# Behavior disclosures

This document describes behaviors that are working as designed but are not obvious
from configuration alone. It is factual and neutral: the goal is that an operator
running this agent understands exactly what it does, what it stores, and what it
sends where.

See also [`SECURITY.md`](../SECURITY.md) and
[`CONFIGURATION.md`](./CONFIGURATION.md).

---

## 1. Browser security-weakening flags

The agent can launch Chromium with security protections disabled. **All of these
default to OFF (secure)**; they are opt-in and boot-fixed (a change applies on
restart). See `CONFIGURATION.md` for the exact env/config keys.

| Flag | Config / env | Chromium effect |
|------|--------------|-----------------|
| Disable sandbox | `WRIT_BROWSER_DISABLE_SANDBOX` | `--no-sandbox` |
| Ignore cert errors | `WRIT_BROWSER_IGNORE_CERT_ERRORS` | `--ignore-certificate-errors` (accepts invalid TLS) |
| Disable web security | `WRIT_BROWSER_DISABLE_WEB_SECURITY` | `--disable-web-security` (drops same-origin policy) |

Additionally, the **always-on** base launch configuration disables cross-site
process isolation and Safe-Browsing auto-update, as is typical for automation
browsers. This is inherent to the automation baseline, not a toggle.

---

## 2. Stealth injection and captcha handling

`js/stealth.js` is injected into **every page on every navigation**. It performs
anti-automation-detection tampering: spoofing `navigator.webdriver`, plugins, and
permissions; WebGL and **canvas** fingerprint tampering; and hardware/screen
spoofing.

**Side effect to be aware of:** the canvas `toDataURL` noise injected for
fingerprint resistance can **corrupt legitimate canvas output** on the pages you
automate — for example a canvas-rendered signature pad, a generated QR code, or any
image your workflow reads back from a canvas. If a workflow depends on exact canvas
pixels, this injection can interfere.

**Captcha handling is detection only.** The agent detects captcha challenges; it
contains **no solver** and does not attempt to bypass them.

Precisely: when a challenge is detected the step returns `captcha_required` and
fails. There is no solver module in this repository to call, so a build made from
this source cannot solve one — a workflow that hits a challenge stops there and
reports it rather than working around it.

---

## 3. What monitoring stores

Content and uptime monitoring persist substantial page data into the local
(SQLCipher-encrypted) database:

- Every detected change stores the **full before/after content** **and** base64
  **before/after screenshots**.
- Selector baselines keep the extracted content plus a baseline screenshot.
- For **login-gated monitors, logged-in page content** (including whatever the
  authenticated page renders) is stored in the DB and is visible through the API /
  UI to anyone with API access.

The data is encrypted at rest (subject to the vault key model in SECURITY.md), but
it is readable by any authenticated API caller and grows with every change.

---

## 4. Silent binary / package downloads

On first browser use the agent downloads **Chromium** if it cannot find one. That
download is made by the agent itself over plain HTTPS — no Python, Node or package
manager involved — and it fetches **open-source Chromium** (BSD-3-Clause) from the
Chromium project's own snapshot bucket, at a revision pinned to a stable release.
It is deliberately *not* "Google Chrome for Testing", which is what the Playwright
tooling installs and which is Google-copyrighted under the Chrome Terms of Service.

**That download is integrity-checked.** The launchable binary is hashed and
compared against a SHA-256 pin compiled into the agent, per revision and platform.
A mismatch, a missing pin, or an unreadable pin table all **fail closed** — the
install is refused rather than completed. Archive entries with unsafe paths are
skipped during extraction.

The separate `writ install-browser` CLI command still shells out to
`patchright`/`playwright`/`npx` where those exist. That path is not pinned, and it
requires an interpreter already on the machine; the built-in downloader above is
what a normal deployment uses.

The **build-time** driver archive (the `playwright` wheel from PyPI /
`files.pythonhosted.org`) **is** SHA-256 pinned against PyPI's published digest,
because that archive contains a `node` binary that is later executed. The build fails closed on a digest mismatch, and a
mirror override (`PLAYWRIGHT_DRIVER_URL`) is refused unless it comes with a
matching `PLAYWRIGHT_DRIVER_SHA256`.

So both the build-time driver fetch and the runtime Chromium download are digest-
pinned and fail closed. If you would rather no runtime download happened at all,
pre-install a browser into `PLAYWRIGHT_BROWSERS_PATH` — the shipped Docker image
does exactly that at build time.

The **driver** never needs a runtime download in a shipped artifact: the release
archives carry it as `playwright-driver/` beside the binary and the container
image carries it at `/app/playwright-driver`, both covered by the release
checksum / image digest. See CONFIGURATION §"Which Playwright driver gets used"
for the resolution order.

**The container image also stages patchright's stealth driver, and that one is
version-pinned but not digest-pinned.** The image build runs
`pip install "patchright==1.60.*"` into a throwaway venv and copies the driver to
`/app/patchright-driver`; the agent prefers it at runtime, so its `node` is the
binary that actually launches your browsers. The `1.60.*` pin is a compatibility
constraint (patchright bundles `playwright-core` 1.60, the protocol the vendored
bindings speak), **not** an integrity one — unlike the build-time Playwright
wheel, there is no SHA-256 to compare against, so a patch release within that
line is trusted on PyPI's word. This applies to **building the image only**:
release archives and a plain `cargo build` never invoke pip. If that matters for
your threat model, build the image with `WRIT_DISABLE_PATCHRIGHT=1` in the
runtime environment (the vanilla driver beside it is digest-pinned), or pin an
exact version and vendor the driver yourself.

---

## 5. Anti-detection interval floors

Monitor check intervals are floored for politeness / anti-detection. The floors
can be **raised** (Settings → Runtime, or `WRIT_HTML_FLOOR_MS` /
`WRIT_JS_FLOOR_MS`) but **never lowered** below the absolute minimums:

| Check type | Minimum interval |
|------------|------------------|
| HTML / HTTP content checks | ≥ 60s |
| Browser (playwright) checks | ≥ 300s |
| Scheduled workflows | ≥ 60s |
| Per-target re-check | 60s |
| Per-check timeout | 90s |

This is why a monitor you set to "every 10s" saves and runs as 60s. It is a floor,
not a paywall.

---

## 6. Retention

The default retention window is **90 days** (`WRIT_RETENTION_DAYS`). The retention
sweep purges rows in the high-churn history tables (runs, changes, uptime checks)
and workflow-output artifacts older than the window. Set `0` to disable the purge
and keep everything. Because `changes` rows carry full before/after content and
base64 screenshots (§3), disabling retention lets the DB grow quickly.

---

## 7. Local runs never auto-retry

A local run that fails is **not** retried automatically. This is a deliberate
safety property — it prevents duplicated submissions / purchases from a retry. Note
that per-workflow `retry_count` / `max_attempts` fields, if present, are silently
ignored on the local path.

---

## 8. AI provider data flow

When you run AI-assisted tasks, prompts together with page **DOM and/or
screenshots** are sent **directly to the AI provider you configured**
(OpenAI / Anthropic / Gemini / an OpenAI-compatible endpoint / Ollama), on your
own key. It does **not** pass through any server of ours on the way. Choose your
provider accordingly, and be aware that page content — potentially including
logged-in page content — is included in those requests.

---

## 9. Local Chrome profile copy (opt-in)

With `WRIT_BROWSER_USE_LOCAL_CHROME` (default OFF), the agent seeds the browser
baseline from your **real local Chrome profile**. This **copies your live Chrome
cookies and storage to disk** under `$WRIT_HOME/.browser_profile` (hardened
0700/0600). It means real authentication cookies land on disk in the agent's data
directory. Only enable this if you understand and accept that.
