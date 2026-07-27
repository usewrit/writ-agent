//! A reqwest DNS resolver that refuses to hand back internal/blocked addresses.
//!
//! SSRF DEFENSE — closes the redirect-rebind and guard-then-dial TOCTOU on the fast-HTTP tiers
//! (monitor checker, crawl shard). Those tiers vet the ENTRY url with a DNS-resolving guard, but
//! reqwest then re-resolves the hostname INDEPENDENTLY at connect time — and again for every redirect
//! hop — so a short-TTL DNS rebind, or a `Location:` pointing at a hostname whose A-record is internal,
//! could still reach loopback / RFC1918 / link-local / cloud-metadata even though the up-front guard
//! passed. Installing this resolver on the client closes both: every address reqwest is about to dial
//! (the initial connection AND each redirect hop) is filtered through [`is_blocked_ip`], and only
//! vetted public addresses survive. If a name resolves ONLY to blocked addresses the resolver yields
//! an empty address set, so the connection fails closed with no internal request ever issued.
//!
//! This changes NO trust decision other than which IPs may be dialed: reqwest still performs TLS
//! against the original hostname (SNI + certificate verification are unaffected — the resolver only
//! selects the destination address hyper connects to).

use std::net::SocketAddr;
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::security::url_guard::is_blocked_ip;

/// A [`reqwest::dns::Resolve`] that strips internal/blocked IPs from every resolution.
#[derive(Debug, Clone, Default)]
pub struct VettingDnsResolver;

impl Resolve for VettingDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str().to_string();
            // Resolve with port 0 — reqwest overrides it with the URL's port (or the scheme default)
            // after we return, per the `reqwest::dns::Resolve` contract.
            let addrs = tokio::net::lookup_host((host.as_str(), 0)).await?;
            // Drop every internal/blocked address. An empty result => connection fails closed.
            let vetted: Vec<SocketAddr> = addrs.filter(|sa| !is_blocked_ip(sa.ip())).collect();
            if vetted.is_empty() {
                tracing::warn!(
                    host = %host,
                    "SSRF blocked: hostname resolved only to internal/blocked addresses (vetting resolver)"
                );
            }
            let iter: Addrs = Box::new(vetted.into_iter());
            Ok(iter)
        })
    }
}

/// Shared handle for the vetting resolver — pass to `reqwest::ClientBuilder::dns_resolver`.
pub fn shared() -> Arc<VettingDnsResolver> {
    Arc::new(VettingDnsResolver)
}
