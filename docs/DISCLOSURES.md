# Behavior disclosures

This document describes behaviors that are working as designed but are not obvious
from configuration alone. It is factual and neutral: the goal is that an operator
running the open agent understands exactly what it does, what it stores, and — if
they link it to a cloud — what that cloud can drive.

See also [`SECURITY.md`](../SECURITY.md) and
[`CONFIGURATION.md`](./CONFIGURATION.md).

---

## 1. Cloud → local capability surface (once linked)

This section applies **only** when you link the daemon to a cloud and the agent
bridge is running (default-on when linked). The self-host `fleet` build has no
cloud link and none of this applies.

Once linked, the cloud can drive the following on the local machine:

- **Run local workflows by id.** The dispatch path loads a workflow by its
  (small, sequential) id and executes it with your local vault credentials,
  returning `extracted_data` to the cloud. A workflow's cloud-callable flag gates
  what is *advertised* to the cloud, and re-checking it on dispatch is the
  fail-closed posture.
- **Run arbitrary ad-hoc recipes**, including steps that resolve local secrets.
  A cloud-authored recipe runs through the engine, which resolves `{{secret:KEY}}`
  / `{{vault:KEY}}` / `{{file:slot}}` from your **local** store. Whoever controls
  the cloud endpoint can therefore construct a recipe that reads a local secret and
  exfiltrates it (via submit or via `extracted_data`).
- **Run AI-browsing tasks on your own AI key.** These can flip the shared browser
  headless and egress via a cloud-supplied proxy.
- **Open interactive / AI / recording sessions on the warm browser.**
  In particular, **`ai_session_close` harvests the session's cookies +
  localStorage and returns them to the cloud.**
- **Start / command / end streaming sessions.**
- **Cancel runs** and **request the catalog** (metadata only).
- Monitoring assignment from the cloud is refused / ack-only.

**The practical implication:** linking to a cloud is a trust decision. An honest
cloud uses this surface for the features you enabled; a compromised or malicious
cloud can use it to enumerate and run your local workflows and read local secrets.
If you need the agent to run workflows without granting a remote party this
surface, use the cloud-free `fleet` build.

### 1a. Supply-pool opt-out is an honest-cloud constraint (TB-3)

The supply-pool opt-out (`WRIT_SUPPLY_POOL` / config) is enforced by inspecting a
tenant stamp on the incoming frame. An unstamped frame is treated as "the owner's
own work." A cloud operator who omits the stamp is not stopped by the opt-out.
This is the correct posture for an untrusted-agent design, but it must be stated
plainly: **the opt-out constrains an honest cloud's routing decisions; it does not
constrain the cloud operator.**

---

## 2. Browser security-weakening flags

The daemon can launch Chromium with security protections disabled. **All of these
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

## 3. Stealth injection and captcha handling

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

Precisely, so you can verify it rather than take our word for it: automated
solving lives behind the `captcha_solver` cargo feature, which is **not** in
`default` and whose source is **not** part of this repository. `automation::step_captcha`
has exactly two arms — a solver pass-through compiled only when that feature is on
(it cannot be, here) and the detection-only arm every build in this repo uses, which
returns `captcha_required` and fails the step. `grep -rn captcha_solver src/` shows
the gate; there is no solver module to call.

---

## 4. What monitoring stores

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

## 5. Silent binary / package downloads

On first browser use the agent shells out to install the browser driver and
Chromium (via the bundled driver CLI; on some paths it may run
`patchright`/`playwright install chromium` or upgrade patchright). There is no
in-crate integrity check on these runtime installs.

The **build-time** driver archive (the `playwright` wheel from PyPI /
`files.pythonhosted.org`) **is** SHA-256 pinned against PyPI's published digest
(`vendor/playwright-rs/build.rs`), because that archive contains a `node` binary
that is later executed. The build fails closed on a digest mismatch, and a
mirror override (`PLAYWRIGHT_DRIVER_URL`) is refused unless it comes with a
matching `PLAYWRIGHT_DRIVER_SHA256`.

Note the asymmetry: the **build-time** driver fetch is pinned, the **runtime**
Chromium/driver installs described above are not. If that matters for your threat
model, pre-install the browsers into `PLAYWRIGHT_BROWSERS_PATH` (the shipped
Docker image does exactly this at build time) so no runtime download happens.

The **driver** never needs a runtime download in a shipped artifact: the release
archives carry it as `playwright-driver/` beside the binary and the container
image carries it at `/app/playwright-driver`, both covered by the release
checksum / image digest. See CONFIGURATION §"Which Playwright driver gets used"
for the resolution order.

---

## 6. Anti-detection interval floors

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

## 7. Retention

The default retention window is **90 days** (`WRIT_RETENTION_DAYS`). The retention
sweep purges rows in the high-churn history tables (runs, changes, uptime checks)
and workflow-output artifacts older than the window. Set `0` to disable the purge
and keep everything. Because `changes` rows carry full before/after content and
base64 screenshots (§4), disabling retention lets the DB grow quickly.

---

## 8. Local runs never auto-retry

A local run that fails is **not** retried automatically. This is a deliberate
safety property — it prevents duplicated submissions / purchases from a retry. Note
that per-workflow `retry_count` / `max_attempts` fields, if present, are silently
ignored on the local path.

---

## 9. The one cloud-reflecting ai-assist endpoint

Almost all AI-assist functionality runs on **your** configured AI provider and key.
There is one exception: the `generate_automation` ai-assist endpoint falls back to
POSTing the full request body to the cloud when **no local AI provider is
configured and the app is linked**. If you have a local AI provider configured, or
you are not linked to a cloud, this fallback does not fire. Every other ai-assist
endpoint stays on your own keys.

---

## 10. AI provider data flow

When you run AI-assisted tasks, prompts together with page **DOM and/or
screenshots** are sent **directly to the AI provider you configured**
(OpenAI / Anthropic / Gemini / an OpenAI-compatible endpoint / Ollama), on your
own key. This data does **not** pass through Writ Cloud. Choose your provider
accordingly, and be aware that page content — potentially including logged-in page
content — is included in those requests.

---

## 11. Local Chrome profile copy (opt-in)

With `WRIT_BROWSER_USE_LOCAL_CHROME` (default OFF), the daemon seeds the browser
baseline from your **real local Chrome profile**. This **copies your live Chrome
cookies and storage to disk** under `$WRIT_HOME/.browser_profile` (hardened
0700/0600). It means real authentication cookies land on disk in the daemon's data
directory. Only enable this if you understand and accept that.
