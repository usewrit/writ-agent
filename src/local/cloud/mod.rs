//! Cloud-link client foundation (Stage A).
//!
//! This module owns the desktop's connection to **Writ Cloud**: the non-secret link metadata
//! ([`state::LinkState`]), the OS-keyring-held account token pair ([`token::TokenPair`]), and the
//! authenticated HTTP client ([`client::CloudClient`]) that carries the `wto_` Bearer and transparently
//! refreshes on a 401.
//!
//! SECURITY BOUNDARY (SECURITY_AND_ENTITLEMENTS_SPEC + the never-trust-a-BYO-agent rule):
//! - The cloud ACCOUNT token (`wto_`/`wtr_`) is STRICTLY SEPARATE from the local-API bearer (`wlt_`,
//!   loopback only) and from the vault root key. It lives ONLY in the OS keyring (`writ-cloud/account`),
//!   never in `writ.db`, never on disk, never logged.
//! - [`state::LinkState`] holds only NON-SECRET reflection metadata (account id/email, base url,
//!   granted scopes, link time) in the encrypted `config` kv table.
//! - This client *carries* credentials to the cloud; it is NOT an authorization gate. Entitlements
//!   and every paid/metered feature are re-enforced SERVER-SIDE per call. Stage B's entitlement
//!   reflection is REFLECTION-ONLY (UI/upsell + offline grace), never an enforcement input.
//!
//! Net-new Rust in this crate behind the `local` feature.

pub mod agent;
pub mod billing;
pub mod channel;
pub mod client;
pub mod crawl;
pub mod entitlements;
pub mod gateway;
pub mod keyless;
pub mod link;
pub mod marketplace;
pub mod notify;
pub mod reflect;
pub mod run_events;
pub mod state;
pub mod sync;
pub mod token;
pub mod usage_metrics;
pub mod workflow_data;

pub use client::CloudClient;
pub use entitlements::{EntitlementClaims, Entitlements};
pub use link::{link_device_flow, unlink, DeviceAuthorization, LinkCallbacks, LinkOutcome};
pub use state::LinkState;
pub use token::TokenPair;
