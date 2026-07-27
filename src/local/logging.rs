//! Tracing redaction for the desktop daemon — re-export of the SHARED sink scrubber.
//!
//! The implementation used to live here, behind the `local` feature. That was the bug: the scrubber
//! is a log-SINK defense, but three of the crate's five tracing initializers are outside the `local`
//! build (the managed-cloud `writ-agent` rolling FILE appender in [`crate::util::logging::init`], the
//! `mcp` stderr sink, the `writ` CLI stderr sink) and therefore had NO redaction at all — anything an
//! event leaked landed verbatim on disk or in an AI IDE's captured logs.
//!
//! So the engine moved to [`crate::util::logging`] (ungated, one copy of the patterns, one writer
//! implementation) and this module re-exports it. Desktop call sites — `local::crash`'s crash-record /
//! diagnostics-bundle scrub and the `writ-agentd` / `writ-agent-fleet` stdout writers — keep their
//! existing `local::logging::…` paths.
//!
//! See [`crate::util::logging`] for the full rationale, the pattern list, and the tests.

pub use crate::util::logging::{
    redact_line, redact_url_for_log, Redacting, RedactingMakeWriter, RedactingWriter,
};
