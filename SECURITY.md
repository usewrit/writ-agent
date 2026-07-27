# Security

This document describes the security model of the `writ-agent` daemon and the
things a self-host operator must know to run it safely. For the full behavior
disclosure list (browser flags, what monitoring stores, the cloud→local
capability surface) see [`docs/DISCLOSURES.md`](./docs/DISCLOSURES.md).

## Reporting a vulnerability

Please report security issues privately through **GitHub Security Advisories**:
use the **"Report a vulnerability"** button under the
[Security tab of this repository](https://github.com/usewrit/writ-agent/security/advisories/new).
Do **not** open a public issue or pull request for an undisclosed vulnerability.

What to expect:

- **Acknowledgement** within 3 business days.
- **Initial assessment** (severity + affected versions) within 7 business days.
- We coordinate a fix and disclosure timeline with you through the advisory
  thread, and credit reporters in the published advisory unless you prefer
  otherwise.

### Supported versions

Security fixes are applied to the latest release line only.

| Version | Supported |
|---------|-----------|
| 1.x (latest release) | Yes |
| Older releases | No — please upgrade |

---

## Vault key model — the single most important item

The daemon stores credentials in a SQLCipher-encrypted database. The database key
(the "vault root") must live somewhere. **By default, the OS keyring is OFF**, and
the vault root is written to a plaintext file:

```
~/.writ/vault.key      # mode 0600, inside a 0700 home directory
```

This means **anything that can read `~/.writ` can decrypt everything** — every
stored secret, cookie, and persona credential. The file permissions (0600 in a
0700 dir) are the only protection at rest in the default configuration.

### Upgrade path: OS keyring

Set `[security].use_keyring = true` in `~/.writ/config.toml` (or
`WRIT_USE_KEYRING=1`) to store the vault root in the OS keyring (Keychain on
macOS) instead of `vault.key`.

**Trade-off / why it is off by default:** on an **unsigned** build the OS may
prompt for keychain access at launch and the daemon can hang before it binds the
loopback port. Enable keyring only once you are running a properly signed build,
or you are prepared for the keychain prompt at boot.

---

## Network exposure and the loopback bearer

The local HTTP/WS API binds **`127.0.0.1:8131`** by default — loopback only. It is
protected by:

- A **bearer token** stored in `~/.writ/runtime.json` (mode 0600). This token is
  the sole authentication gate for the API.
- A **loopback + DNS-rebind guard**: Origin/Host validation as a single choke
  point, so a malicious web page cannot drive the local API via the browser.

### LAN exposure implications — read before enabling

You can bind the API to `0.0.0.0` (LAN-reachable) via the in-app Network toggle,
or via `WRIT_NETWORK_EXPOSE=1`. In a release build the env override is honored
**only** if you also set `WRIT_ALLOW_ENV_EXPOSE=1`, so a stray/injected env var
(a poisoned launch agent or shell profile) cannot silently expose the API
LAN-wide.

**When exposed, the bearer token is the *only* gate.** Anyone on the LAN who
obtains the `wlt_` / `wlk_` token gets full access — including **admin**
operations: factory-wipe (`data/reset`), DB swap (`backup/restore`), key minting,
`network/expose`, `cloud/unlink`, and reading every stored secret. The current
scope model is coarse: an `admin` key is effectively full device control (see
DISCLOSURES §"Scope model"). Treat LAN exposure as granting full device control to
anyone holding the token. Prefer keeping the API on loopback and reaching it
through an authenticated reverse proxy or SSH tunnel.

---

## Entitlements key pinning

Cloud/self-host entitlements are signature-verified against a pinned public key
(`src/local/cloud/entitlements.rs`, `PINNED_KEYS`).

`PINNED_KEYS` ships **empty on purpose**, and the verifier **fails closed**: with no
pinned key, every entitlement manifest is rejected as `unknown_kid`. The dev/test key
lives in a separate `TEST_PINNED_KEYS` table gated behind
`#[cfg(any(test, feature = "update-test-keys"))]` — an opt-in Cargo feature that is
absent from `default` and from every shipped feature set, so **no build a user runs
(debug or release) trusts it**. Its private half is committed in the test module of
that same file on purpose; a CI guard fails the moment a *real* key is committed
alongside its private half.

Entitlement checking is **reflection-only** in any case — the server re-enforces
every limit — so an empty key table degrades gracefully rather than granting
anything. A deployer who wants local entitlement reflection adds their own
production `kid` + PEM to `PINNED_KEYS`; nobody needs to remove anything first.

---

## App-lock

The daemon supports an app-lock (a passphrase/PIN gate over secret-read routes):

- The daemon **starts locked**; the vault root is wrapped (root XOR Argon2id,
  constant-time verify) and secret reads return `423 Locked` until unlocked.
- Unlock is required before secret-read routes serve data.

Operators should be aware that the app-lock protects secret *reads* while locked;
review `docs/DISCLOSURES.md` and your build for the exact routes gated by the lock.

---

## Threat-model summary

- **At rest, default:** protected by file permissions (`vault.key` 0600) — not by
  a separate secret. Enable keyring for defense-in-depth.
- **On the network, default:** loopback-only + bearer token + DNS-rebind guard.
- **LAN-exposed:** bearer token is the sole gate; anyone with it has full,
  admin-level control.
- **Cloud link (optional):** once linked, the cloud can drive a broad set of local
  operations — see `docs/DISCLOSURES.md`. The self-host `fleet` build has no cloud
  link.
