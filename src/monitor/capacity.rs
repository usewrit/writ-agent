//! Hardware-derived capacity. Port of the relevant maths in
//! `desktop-agent/lib/hardware_profiler.py` (HTTP mode). Produces the `capacity`
//! object advertised on connect and consumed by the backend distributor.

use serde::Serialize;
use sysinfo::System;

// Resource cost per HTTP check / safety margins — same constants as Python.
const HTTP_CPU_PERCENT: f64 = 0.5;
const HTTP_RAM_MB: f64 = 10.0;
const CPU_RESERVE_PERCENT: f64 = 20.0;
const RAM_RESERVE_PERCENT: f64 = 25.0;
const THREAD_POOL_STARTUP_MS: f64 = 50.0;
const COORDINATION_OVERHEAD_MS: f64 = 15.0;
const CONSERVATIVE_MARGIN: f64 = 0.65;

// Default latency model when we haven't benchmarked (Python's fallback).
const DEFAULT_AVG_LATENCY_MS: f64 = 200.0;
const DEFAULT_P95_LATENCY_MS: f64 = 350.0;

/// Capacity report — field names match `agent.meta['capacity']` on the backend.
#[derive(Debug, Clone, Serialize)]
pub struct CapacityReport {
    pub cpu_cores: usize,
    pub cpu_threads: usize,
    pub ram_total_gb: f64,
    pub check_mode: String,
    pub parallel_workers: usize,
    pub avg_check_latency_ms: f64,
    pub timeslots_needed: usize,
    pub targets_per_timeslot: usize,
    pub total_capacity: usize,
}

impl CapacityReport {
    /// Profile the host and compute capacity for the given global period.
    pub fn profile(global_period_ms: i64) -> Self {
        let mut sys = System::new();
        sys.refresh_memory();
        // CPU usage is a DELTA between two refreshes: the very first `refresh_cpu_usage()` has no prior
        // sample and reports ~0%, which would over-estimate available CPU (→ inflated worker count).
        // Prime, wait the library's minimum sampling interval, then refresh again for a real reading.
        sys.refresh_cpu_usage();
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        sys.refresh_cpu_usage();

        let cpu_threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        let cpu_cores = (cpu_threads / 2).max(1);
        let ram_total_gb = sys.total_memory() as f64 / 1_073_741_824.0; // bytes → GiB
        let ram_available_gb = sys.available_memory() as f64 / 1_073_741_824.0;
        let cpu_usage_percent = sys.global_cpu_info().cpu_usage() as f64;

        let parallel_workers =
            Self::parallel_workers(cpu_threads, ram_total_gb, ram_available_gb, cpu_usage_percent);

        let targets_per_timeslot =
            Self::targets_per_timeslot(global_period_ms.max(1) as f64, parallel_workers);

        // One timeslot is enough for a single agent; the backend expands slots
        // across the fleet. We advertise a single slot of our realistic capacity.
        let timeslots_needed = 1;
        let total_capacity = targets_per_timeslot * timeslots_needed;

        Self {
            cpu_cores,
            cpu_threads,
            ram_total_gb,
            check_mode: "http".to_string(),
            parallel_workers,
            avg_check_latency_ms: DEFAULT_AVG_LATENCY_MS,
            timeslots_needed,
            targets_per_timeslot,
            total_capacity,
        }
    }

    fn parallel_workers(
        cpu_threads: usize,
        ram_total_gb: f64,
        ram_available_gb: f64,
        cpu_usage_percent: f64,
    ) -> usize {
        let available_cpu_percent =
            (100.0 - CPU_RESERVE_PERCENT - cpu_usage_percent).clamp(10.0, 80.0);
        let mut available_ram_gb = ram_total_gb * (1.0 - RAM_RESERVE_PERCENT / 100.0);
        available_ram_gb = available_ram_gb.min(ram_available_gb).max(0.0);

        let max_workers_cpu = (available_cpu_percent / HTTP_CPU_PERCENT) as i64;
        let max_workers_ram = ((available_ram_gb * 1024.0) / HTTP_RAM_MB) as i64;
        let mut max_workers = max_workers_cpu.min(max_workers_ram);
        // HTTP is I/O bound — allow more parallelism than threads.
        max_workers = max_workers.min(cpu_threads as i64 * 10);
        max_workers.clamp(1, 200) as usize
    }

    /// Realistic per-timeslot target capacity (Python
    /// `calculate_timeslot_capacity_realistic`, conservative margin).
    fn targets_per_timeslot(timeslot_duration_ms: f64, parallel_workers: usize) -> usize {
        let effective_time = (timeslot_duration_ms - THREAD_POOL_STARTUP_MS).max(0.0);
        let effective_latency_p95 = DEFAULT_P95_LATENCY_MS + COORDINATION_OVERHEAD_MS;
        let batches = if effective_latency_p95 > 0.0 {
            effective_time / effective_latency_p95
        } else {
            0.0
        };
        let realistic = (batches * parallel_workers as f64) as i64;
        ((realistic as f64 * CONSERVATIVE_MARGIN) as i64).max(1) as usize
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({}))
    }
}
