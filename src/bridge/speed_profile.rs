//! Startup CPU speed profile for the agent.
//!
//! Computes a small hardware/perf fingerprint ONCE at agent startup (see
//! `SpeedProfile::compute`) and the bridge caches it, reusing it in the
//! `/api/recorder/connect` body and in every heartbeat so the backend can
//! rank/route work by single-core speed and refresh on VM resize.
//!
//! Everything here is best-effort and synchronous: a failure must NEVER block
//! connect. Unknown numeric fields fall back to 0 (the backend then derives a
//! class from clock/capacity) and the benchmark falls back to perf_score = 0.
//! No async, no shared state, no new heavy deps — pure local CPU/env reading.

use serde::Serialize;
use std::time::{Duration, Instant};

/// Calibration constant for the single-core benchmark.
///
/// The benchmark runs a tight xorshift64 integer loop for a fixed ~120ms budget
/// on one thread and counts iterations, then computes iterations-per-ms and
/// divides by this constant to normalise onto the target scale:
///   - a modern fast core (~2020+, high GHz)  -> ~2000-3500
///   - an old low-clock server core (~1.7GHz) -> ~800-1200
///
/// Native Rust (release-optimised) runs this loop FAR faster than CPython.
/// Measured empirically: a top-end modern core (Apple Silicon, -O) executes this
/// xorshift loop at ~900k effective iterations/ms; dividing by ~300.0 maps it to
/// ~3000 (high end of the band) and scales an old ~1.7GHz core into the
/// ~800-1200 range, hitting the target scale (fast ~2000-3500, old-slow ~800-1200).
/// (Tune if compiler/opt-level changes shift throughput materially.)
const RUST_CALIBRATION: f64 = 300.0;

/// Fixed wall-time budget for the benchmark loop. Capped so startup is never
/// delayed more than ~150ms.
const BENCH_BUDGET: Duration = Duration::from_millis(120);

#[derive(Debug, Clone, Serialize)]
pub struct SpeedProfile {
    /// Operator's explicit tag from AGENT_SPEED_CLASS ("fast"|"throughput"|"balanced"); null if unset.
    pub speed_class: Option<String>,
    /// Normalised single-core benchmark score (0 on failure).
    pub perf_score: i64,
    /// Physical cores (0 if unknown).
    pub cpu_cores: i64,
    /// Logical cores / threads (0 if unknown).
    pub cpu_threads: i64,
    /// Nominal/max CPU clock in MHz (0 if unknown).
    pub cpu_clock_mhz: i64,
    /// Total system RAM in MB (0 if unknown).
    pub ram_mb: i64,
}

impl SpeedProfile {
    /// Compute the full profile. Best-effort; never panics.
    pub fn compute() -> Self {
        // One System instance serves both physical-core count and RAM.
        let mut sys = sysinfo::System::new();
        sys.refresh_memory();

        let cpu_threads = std::thread::available_parallelism()
            .map(|n| n.get() as i64)
            .unwrap_or(0);
        let cpu_cores = sys
            .physical_core_count()
            .map(|c| c as i64)
            .filter(|&c| c > 0)
            .unwrap_or(cpu_threads);
        // sysinfo 0.30 reports memory in BYTES.
        let ram_mb = (sys.total_memory() / (1024 * 1024)) as i64;

        SpeedProfile {
            speed_class: speed_class_env(),
            perf_score: run_benchmark().unwrap_or(0),
            cpu_cores,
            cpu_threads,
            cpu_clock_mhz: cpu_clock_mhz(),
            ram_mb,
        }
    }

    /// Merge the 6 fields into an existing JSON object (e.g. the connect body or
    /// a heartbeat) so callers can splice them into the wire message.
    pub fn inject_into(&self, obj: &mut serde_json::Map<String, serde_json::Value>) {
        obj.insert("speed_class".into(), serde_json::json!(self.speed_class));
        obj.insert("perf_score".into(), serde_json::json!(self.perf_score));
        obj.insert("cpu_cores".into(), serde_json::json!(self.cpu_cores));
        obj.insert("cpu_threads".into(), serde_json::json!(self.cpu_threads));
        obj.insert("cpu_clock_mhz".into(), serde_json::json!(self.cpu_clock_mhz));
        obj.insert("ram_mb".into(), serde_json::json!(self.ram_mb));
    }
}

/// Operator's explicit tag from AGENT_SPEED_CLASS, validated. None if unset/invalid.
fn speed_class_env() -> Option<String> {
    match std::env::var("AGENT_SPEED_CLASS") {
        Ok(v) => {
            let v = v.trim().to_lowercase();
            if v == "fast" || v == "throughput" || v == "balanced" {
                Some(v)
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

/// Single-core integer benchmark → normalised perf_score. Returns None on failure
/// (caller maps to 0). xorshift64 tight loop for a fixed time budget on one thread.
fn run_benchmark() -> Option<i64> {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15; // non-zero seed
    let mut iters: u64 = 0;
    // Work in fixed chunks so we read the clock infrequently (clock reads are
    // relatively expensive vs the loop body).
    const CHUNK: u64 = 8192;
    let start = Instant::now();
    loop {
        for _ in 0..CHUNK {
            // xorshift64 — pure integer arithmetic, wrapping to avoid overflow panics.
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            // Consume x so the optimiser can't eliminate the loop.
            iters = iters.wrapping_add(x & 1);
        }
        iters = iters.wrapping_add(CHUNK);
        if start.elapsed() >= BENCH_BUDGET {
            break;
        }
    }
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    if elapsed_ms <= 0.0 {
        return None;
    }
    let iters_per_ms = iters as f64 / elapsed_ms;
    let score = (iters_per_ms / RUST_CALIBRATION) as i64;
    Some(score.max(0))
}

/// Nominal/max CPU clock in MHz. Reads /proc/cpuinfo on Linux; 0 elsewhere/unknown.
fn cpu_clock_mhz() -> i64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(contents) = std::fs::read_to_string("/proc/cpuinfo") {
            let mut best: f64 = 0.0;
            for line in contents.lines() {
                let lower = line.to_lowercase();
                if lower.starts_with("cpu mhz") {
                    if let Some((_, v)) = line.split_once(':') {
                        if let Ok(mhz) = v.trim().parse::<f64>() {
                            if mhz > best {
                                best = mhz;
                            }
                        }
                    }
                }
            }
            return best as i64;
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}
