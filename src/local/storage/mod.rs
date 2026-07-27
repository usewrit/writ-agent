//! Storage — on-disk byte I/O for file assets, encrypted at rest (Layer C).
//!
//! The `stored_files` table holds metadata + a `storage_key`; the bytes themselves live under
//! `~/.writ/files/<storage_key>` as a `WFB1` envelope sealed with the vault's K_file subkey
//! (see `vault::encrypt_file`). Nothing on disk is ever plaintext. Workflow OUTPUT artifacts
//! (screenshots, replay downloads) are also encrypted via this path and registered as
//! `source='workflow_output'` handles.
//!
//! `materialize_for_run` is the one exception that touches plaintext: Playwright's
//! `setInputFiles` needs a real path, so we decrypt into a `0600` tempfile guarded by `TempGuard`,
//! which best-effort overwrites + unlinks the plaintext on `Drop`.
//!
//! Net-new Rust — NOT ported from the legacy Python `desktop-agent`.

pub mod files;

pub use files::{
    capture_output, create_file, local_path_for_run, materialize_for_run, read_file_bytes,
    storage_path_for_key, TempGuard,
};
