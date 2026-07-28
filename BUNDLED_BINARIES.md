# Bundled binaries — attribution

[`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md) is generated from the locked Cargo dependency
graph, so it covers **Rust crates only**. This file covers the third-party programs that are
*redistributed as binaries* in the artifacts published from this repository — `cargo-about` cannot
see them, and their licenses still require attribution when they are shipped.

Nothing here is AGPL, and nothing here imposes copyleft on this project: each is permissively
licensed and redistributed **unmodified**.

## What ships where

| Component | License | In release archives | In the container image |
| --- | --- | --- | --- |
| **Playwright driver** (`playwright-driver/`) — the Node.js driver extracted from the PyPI `playwright` wheel | Apache-2.0 | yes | yes (`/app/playwright-driver`) |
| **Node.js** — the `node` executable inside each driver directory | MIT (plus its own bundled dependencies, see the runtime's own notices) | yes | yes |
| **patchright driver** (`patchright-driver/`) — stealth-patched Playwright fork, from the PyPI `patchright` package | Apache-2.0 | no | yes (`/app/patchright-driver`) |
| **Chromium** — installed by the driver CLI | BSD-3-Clause, plus the licenses enumerated in Chromium's own `LICENSE` and `third_party/` tree | no (downloaded on first browser use) | yes (`PLAYWRIGHT_BROWSERS_PATH=/ms-playwright`) |

A plain `cargo build` produces none of these; the driver arrives at build time and Chromium on first
browser use. See [`docs/DISCLOSURES.md`](./docs/DISCLOSURES.md) §5 for the download and integrity
story, including which of them are digest-pinned.

## Notices

### Playwright and the patchright fork — Apache License 2.0

Playwright is Copyright (c) Microsoft Corporation, licensed under the Apache License, Version 2.0.
patchright ([`Kaliiiiiiiiii-Vinyzu/patchright-python`](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright-python))
is a fork of Playwright, also under the Apache License, Version 2.0.

You may obtain a copy of the License at <http://www.apache.org/licenses/LICENSE-2.0>. Unless required
by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under the License.

The full license text ships inside each driver directory, and the complete Apache-2.0 text also
appears in [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md) (many Rust crates use it).

### Node.js — MIT License

The `node` executable bundled inside each driver directory is distributed under the MIT License,
Copyright Node.js contributors. Node.js itself embeds further third-party components under their own
licenses; the authoritative list is the `LICENSE` file shipped in the Node.js distribution.

### Chromium — BSD-3-Clause and others

Chromium is Copyright 2015 The Chromium Authors, licensed under a BSD-3-Clause license, and embeds a
large number of third-party components under their own terms. The authoritative notices are the
`LICENSE` file and `third_party/` tree inside the installed browser, under
`PLAYWRIGHT_BROWSERS_PATH` (`/ms-playwright` in the container image). Chromium is **not** included in
the release archives — the driver downloads it on first browser use.

---

**Maintainers:** if you add a binary to a shipped artifact, add it here in the same change.
`cargo deny` and `cargo about` will not catch it — they only see the Cargo graph, which is exactly
why this file exists.
