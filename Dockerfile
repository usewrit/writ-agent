# Writ self-host fleet worker (`writ-agent-fleet`) container image.
# ---------------------------------------------------------------------------
# This image builds and ships the OSS SELF-HOST FLEET build — the
# `writ-agent-fleet` binary (`--no-default-features --features local,fleet,openai`;
# no cloud code compiles into it). It is what self-hosters run as
# ghcr.io/usewrit/writ-agent:latest: a pure execution node that dials out to a
# self-host coordinator (WRIT_COORDINATOR_URL + WRIT_SERVICE_TOKEN) and runs
# deployed/dispatched workflows fully inside the container.
#
# Browsers: the vendored playwright-rs fork bundles a Node.js Playwright driver
# (downloaded, checksum-pinned, by vendor/playwright-rs/build.rs into the build's
# OUT_DIR). We drive THAT bundled driver to install Chromium at build time into a
# stable PLAYWRIGHT_BROWSERS_PATH and copy it into the runtime stage — so the
# runtime image needs neither pip/patchright nor node/npx. (At runtime the app
# also falls back to src/browser/install.rs auto-install, but that requires a
# Playwright/patchright CLI that this image intentionally does not ship.)
#
# Health: the worker serves a loopback-only status endpoint when
# WRIT_FLEET_STATUS_PORT is set (baked to 9444 below); the HEALTHCHECK curls
# /healthz, which returns 503 while the worker is disconnected from the
# coordinator — so orchestrators see a wedged/disconnected worker as unhealthy.
# ---------------------------------------------------------------------------

# Stage 1: Build
#
# The builder base MUST match the runtime base's Debian release. `rust:1.95-slim` floats to the
# newest Debian (trixie, glibc 2.41) while the runtime stage below is bookworm (glibc 2.36) — a
# binary linked against the newer glibc fails to start with `GLIBC_2.4x not found`. Pin the builder
# to bookworm explicitly so the two stages can never drift apart again.
FROM rust:1.95-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies. `make` + `perl` are required by the `local` feature's
# bundled SQLCipher + vendored OpenSSL (libsqlite3-sys bundled-sqlcipher-vendored-openssl).
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    make \
    perl \
    && rm -rf /var/lib/apt/lists/*

# Browsers are installed into a stable, image-wide path (not $HOME/.cache) so the
# location is identical in the builder and runtime stages.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Copy manifests + the vendored playwright-rs fork ([patch.crates-io] target)
# first for layer caching. Every [[bin]] path must exist for the manifest to
# resolve, so stub them all for the dependency-priming build.
COPY Cargo.toml Cargo.lock* ./
COPY vendor/ vendor/
RUN mkdir -p src/bin \
    && echo "fn main() {}" > src/main.rs \
    && echo "" > src/lib.rs \
    && echo "fn main() {}" > src/bin/writ-agentd.rs \
    && echo "fn main() {}" > src/bin/writ.rs \
    && echo "fn main() {}" > src/bin/writ-agent-fleet.rs
RUN cargo build --release --no-default-features --features local,fleet,openai --bin writ-agent-fleet || true
RUN rm -rf src

# Copy full source (migrations/ is embedded at compile time via sqlx::migrate!).
COPY src/ src/
COPY js/ js/
COPY migrations/ migrations/

# Build the release fleet worker (cloud-free OSS feature set).
RUN cargo build --release --no-default-features --features local,fleet,openai --bin writ-agent-fleet

# Stage the vendored Playwright driver (node + package/cli.js) at a STABLE path, then use it to
# install Chromium. No pip/patchright/npx needed.
#
# The staging step is not cosmetic. build.rs bakes an ABSOLUTE path to the driver into the binary —
# either this build's `OUT_DIR` or `~/.cache/playwright-rs-driver/…` — and the runtime stage below
# is a different filesystem, so that path resolves to nothing and the first browser launch fails
# with `ServerNotFound`. Copying the driver to a fixed location lets the runtime stage carry it
# next to the binary, where `browser::install::find_sibling_driver` picks it up.
# Both build.rs outcomes are handled, and a miss is a hard error rather than an empty `$CLI_JS`
# that fails later with an unreadable message.
RUN set -eux; \
    CLI_JS="$(find target/release/build "$HOME/.cache/playwright-rs-driver" \
                   -type f -path '*/package/cli.js' 2>/dev/null | head -n1)"; \
    if [ -z "$CLI_JS" ]; then echo "FATAL: no Playwright driver produced by build.rs" >&2; exit 1; fi; \
    DRIVER_DIR="$(dirname "$(dirname "$CLI_JS")")"; \
    mkdir -p /opt/playwright-driver; \
    cp -a "$DRIVER_DIR/." /opt/playwright-driver/; \
    test -x /opt/playwright-driver/node; \
    /opt/playwright-driver/node /opt/playwright-driver/package/cli.js install --with-deps chromium

# Stage 2: Runtime
FROM debian:bookworm-slim

# Must match the builder stage so the app finds the copied browsers.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
# Data home (encrypted writ.db + vault.key). Mount a volume here to persist
# deployed workflows/secrets and the agent identity across container restarts.
ENV WRIT_HOME=/data
# Loopback-only /healthz status listener (see writ-agent-fleet docs). The port is
# never exposed off-host; the in-container HEALTHCHECK below is its only consumer.
ENV WRIT_FLEET_STATUS_PORT=9444

# Install runtime dependencies (browser shared libs + curl for the HEALTHCHECK).
# The fleet worker forces headless browsers, so no Xvfb/X11 is needed.
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    curl \
    gnupg \
    ca-certificates \
    tini \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libatspi2.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    xdg-utils \
    libu2f-udev \
    libvulkan1 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN mkdir -p /app/logs /data

# Copy the fleet worker binary from the builder (migrations are compiled in).
COPY --from=builder /app/target/release/writ-agent-fleet /app/writ-agent-fleet

# ...and the Playwright driver NEXT TO it. The binary's compile-time driver path pointed into the
# builder stage, which does not exist here; `browser::install::find_sibling_driver` looks for
# `<exe dir>/playwright-driver` precisely so this copy is all that is needed. Without it the image
# starts, connects, reports healthy — and then fails every run at browser launch.
COPY --from=builder /opt/playwright-driver /app/playwright-driver

# Create a dedicated non-root user. Chromium runs under this user; its own
# sandbox is managed by the app (see browser/context.rs) — we deliberately do NOT
# add --no-sandbox here.
RUN useradd -m -u 1000 appuser \
    && chown -R appuser:appuser /app /data

# Copy the pre-installed browsers and hand them to the runtime user.
COPY --from=builder /ms-playwright /ms-playwright
RUN chown -R appuser:appuser /ms-playwright

USER appuser

VOLUME ["/data"]

# /healthz replies 200 while connected to the coordinator, 503 while
# disconnected/wedged — `curl -f` turns the 503 into an unhealthy container.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f "http://127.0.0.1:${WRIT_FLEET_STATUS_PORT}/healthz" || exit 1

# `tini` as PID 1. The worker spawns the Playwright node driver, which spawns Chromium, which
# spawns renderer/GPU children; without an init those become zombies because the worker (as PID 1)
# does not reap unrelated orphans. tini also forwards SIGTERM so the graceful drain actually runs.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["./writ-agent-fleet"]

# ---------------------------------------------------------------------------
# GIVE THE DRAIN ROOM TO FINISH.
#
# On SIGTERM the worker drains in-flight runs (default `WRIT_FLEET_DRAIN_TIMEOUT_S=30`) so their
# `task_result` frames reach the coordinator instead of leaving it waiting on a future that never
# resolves. Docker's default `docker stop` grace is **10s**, which SIGKILLs that drain part-way.
#
# `STOPSIGNAL`/`--stop-timeout` is the image-level half; the operator side must match:
#   docker run  --stop-timeout 45 …
#   compose     stop_grace_period: 45s
#   systemd     TimeoutStopSec=45
#   k8s         terminationGracePeriodSeconds: 45
# Keep the grace ABOVE `WRIT_FLEET_DRAIN_TIMEOUT_S`. Behaviour is strictly better than before even
# without it (10s of draining beats 0), but a partial drain still abandons whatever was left.
STOPSIGNAL SIGTERM
