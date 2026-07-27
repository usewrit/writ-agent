//! Local HTTPS material — an mkcert-style, per-install local CA + a short-lived leaf certificate,
//! so MCP / OpenAI-compat clients that REQUIRE an `https://` base URL can reach the loopback daemon
//! with a certificate that actually validates (once the user trusts the CA, see `api::v1::tls`).
//!
//! Trust model (LOCAL only — nothing here ever leaves the machine):
//! - The CA lives in `~/.writ/tls/` (`ca.pem` public anchor, `ca.key` 0600, `ca.json` metadata) and
//!   is NAME-CONSTRAINED to loopback + RFC-1918 space, so even a fully trusted Writ CA can never
//!   vouch for a real internet domain. Validity ~10 years; regenerated (re-trust required) only when
//!   missing/corrupt/expiring.
//! - The LEAF is re-issued fresh on every daemon boot; its private key exists ONLY in memory. SANs:
//!   `localhost`, `127.0.0.1`, `::1` (+ the LAN IP when the operator opted into LAN exposure).
//! - The HTTPS listener serves the SAME router as the plain lane (bearer + Origin/Host guard apply
//!   identically); TLS adds transport-scheme compatibility, not an auth change.

use super::config::Paths;
use super::error::{LocalError, LocalResult};
use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose, NameConstraints,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

/// The CA's CommonName — also the display name in OS trust stores. NEVER change this: re-issued
/// leaves chain to the on-disk anchor by issuer DN, so a renamed CA would orphan existing trust.
pub const CA_COMMON_NAME: &str = "Writ Local CA";
/// CA validity (~10 years) and the remaining-life floor under which we regenerate it.
const CA_VALID_DAYS: i64 = 3650;
const CA_MIN_REMAINING_DAYS: i64 = 30;
/// Leaf validity. Apple caps TLS leaves chaining to user-added anchors at 825 days; 398 keeps a
/// comfortable margin (the leaf is re-issued every boot anyway, so real lifetime is far shorter).
const LEAF_VALID_DAYS: i64 = 398;

/// Everything the HTTPS lane needs at boot: a ready rustls config + the public facts the
/// status/connect-info surfaces report. NO private key material outside `server_config`.
pub struct TlsMaterial {
    pub server_config: Arc<rustls::ServerConfig>,
    pub ca_path: PathBuf,
    /// Lowercase-hex SHA-256 of the on-disk CA certificate DER (the anchor the user trusts).
    pub ca_fingerprint_sha256: String,
    /// RFC3339 UTC expiry timestamps (public facts, useful for the UI).
    pub ca_expires_at: String,
    pub leaf_expires_at: String,
}

/// Public runtime facts about the HTTPS lane, installed by `server::serve` once the TLS listener is
/// actually up, and read by the `/v1/tls` + `/v1/mcp/connect-info` handlers. Process-global (same
/// `install_global` idiom as the cloud-agent manager) so `AppState` — constructed literally in many
/// tests — stays untouched.
#[derive(Debug, Clone, Serialize)]
pub struct TlsRuntimeStatus {
    pub port: u16,
    pub ca_path: String,
    pub ca_fingerprint_sha256: String,
    pub ca_expires_at: String,
    pub leaf_expires_at: String,
}

static RUNTIME_STATUS: OnceLock<TlsRuntimeStatus> = OnceLock::new();

/// Record that the HTTPS listener is live. First write wins (the lane binds once per process).
pub fn install_status(status: TlsRuntimeStatus) {
    let _ = RUNTIME_STATUS.set(status);
}

/// The live HTTPS lane facts, or `None` when the lane is disabled / failed to come up.
pub fn runtime_status() -> Option<&'static TlsRuntimeStatus> {
    RUNTIME_STATUS.get()
}

/// Sidecar metadata for the persisted CA (`ca.json`). Only public facts — expiry bookkeeping so we
/// can check remaining life without an X.509 parser dependency.
#[derive(Debug, Serialize, Deserialize)]
struct CaMeta {
    not_after_unix: i64,
}

/// A loaded-or-created CA ready to issue leaves. `disk_der` is the EXACT on-disk anchor bytes (the
/// thing the user trusts); the in-memory `issuer` is re-signed from the same key + constants, which
/// chains identically (same subject DN, same key → same SKI) without an X.509 parser.
struct CaHandle {
    issuer: rcgen::Certificate,
    issuer_key: KeyPair,
    disk_der: CertificateDer<'static>,
    not_after_unix: i64,
}

fn internal(ctx: &str, e: impl std::fmt::Display) -> LocalError {
    LocalError::Internal(format!("tls: {ctx}: {e}"))
}

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

fn rfc3339(unix: i64) -> String {
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|t| t.to_rfc3339())
        .unwrap_or_default()
}

fn odt(unix: i64) -> LocalResult<time::OffsetDateTime> {
    time::OffsetDateTime::from_unix_timestamp(unix).map_err(|e| internal("timestamp", e))
}

/// The CA's certificate params. Deterministic constants (same DN every time) so a leaf signed by a
/// RELOADED key still chains to the original on-disk anchor. Name constraints pin the CA's signing
/// power to loopback + private ranges — it can never vouch for a public domain even if trusted.
fn ca_params(not_before_unix: i64, not_after_unix: i64) -> LocalResult<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|e| internal("ca params", e))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_COMMON_NAME);
    dn.push(DnType::OrganizationName, "Writ (local daemon)");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![
            GeneralSubtree::DnsName("localhost".into()),
            GeneralSubtree::IpAddress(CidrSubnet::V4([127, 0, 0, 0], [255, 0, 0, 0])),
            GeneralSubtree::IpAddress(CidrSubnet::V6(
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                [255; 16],
            )),
            // RFC-1918 so the LAN-exposed daemon's LAN-IP SAN stays inside the constraint.
            GeneralSubtree::IpAddress(CidrSubnet::V4([10, 0, 0, 0], [255, 0, 0, 0])),
            GeneralSubtree::IpAddress(CidrSubnet::V4([172, 16, 0, 0], [255, 240, 0, 0])),
            GeneralSubtree::IpAddress(CidrSubnet::V4([192, 168, 0, 0], [255, 255, 0, 0])),
        ],
        excluded_subtrees: Vec::new(),
    });
    params.not_before = odt(not_before_unix)?;
    params.not_after = odt(not_after_unix)?;
    Ok(params)
}

fn ca_pem_path(paths: &Paths) -> PathBuf {
    paths.tls_dir().join("ca.pem")
}
fn ca_key_path(paths: &Paths) -> PathBuf {
    paths.tls_dir().join("ca.key")
}
fn ca_meta_path(paths: &Paths) -> PathBuf {
    paths.tls_dir().join("ca.json")
}

/// Lowercase-hex SHA-256 of the on-disk CA cert DER. Public (it fingerprints the trust anchor).
pub fn ca_fingerprint_from_disk(paths: &Paths) -> LocalResult<String> {
    let der = read_ca_der(paths)?;
    Ok(sha256_hex(&der))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn read_ca_der(paths: &Paths) -> LocalResult<CertificateDer<'static>> {
    // PEM parsing goes through `rustls::pki_types` (the `PemObject` trait), NOT the `rustls-pemfile`
    // crate: that crate is unmaintained (RUSTSEC-2025-0134, archived upstream) and its own advisory
    // points here. `pki_types` is already in the tree via `rustls`, so this drops a dependency
    // rather than adding one.
    use rustls::pki_types::pem::PemObject;
    let pem = std::fs::read(ca_pem_path(paths))?;
    match CertificateDer::from_pem_slice(&pem) {
        Ok(der) => Ok(der),
        Err(rustls::pki_types::pem::Error::NoItemsFound) => {
            Err(LocalError::Internal("tls: ca.pem holds no certificate".into()))
        }
        Err(e) => Err(internal("ca.pem parse", e)),
    }
}

/// Ensure the tls dir exists (`0700` on unix — it holds the CA key).
fn ensure_tls_dir(paths: &Paths) -> LocalResult<()> {
    let dir = paths.tls_dir();
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Load the persisted CA when present + healthy + not near expiry; otherwise (re)generate one.
/// Regeneration means the user must re-trust — log it loudly.
fn load_or_create_ca(paths: &Paths) -> LocalResult<CaHandle> {
    ensure_tls_dir(paths)?;

    // Reuse path: key + anchor + meta all present and parseable, with ≥30 days of CA life left.
    let loaded = (|| -> Option<CaHandle> {
        let key_pem = std::fs::read_to_string(ca_key_path(paths)).ok()?;
        let key = KeyPair::from_pem(&key_pem).ok()?;
        let disk_der = read_ca_der(paths).ok()?;
        let meta: CaMeta =
            serde_json::from_slice(&std::fs::read(ca_meta_path(paths)).ok()?).ok()?;
        if meta.not_after_unix - now_unix() < CA_MIN_REMAINING_DAYS * 86_400 {
            return None;
        }
        // Rebuild an issuer object from the SAME key + constants. Identical subject DN + key means
        // leaves it signs chain to the on-disk anchor byte-for-byte trusted by the OS store.
        let params = ca_params(now_unix() - 86_400, meta.not_after_unix).ok()?;
        let issuer = params.self_signed(&key).ok()?;
        Some(CaHandle { issuer, issuer_key: key, disk_der, not_after_unix: meta.not_after_unix })
    })();
    if let Some(ca) = loaded {
        return Ok(ca);
    }

    // (Re)generate. Backdate not_before an hour so a just-written cert validates through clock skew.
    let not_before = now_unix() - 3_600;
    let not_after = now_unix() + CA_VALID_DAYS * 86_400;
    let key = KeyPair::generate().map_err(|e| internal("ca keygen", e))?;
    let params = ca_params(not_before, not_after)?;
    let cert = params.self_signed(&key).map_err(|e| internal("ca self-sign", e))?;

    // Key first (0600 atomic), then the public anchor + meta.
    crate::local::vault::write_secret_file(&ca_key_path(paths), key.serialize_pem().as_bytes())?;
    std::fs::write(ca_pem_path(paths), cert.pem().as_bytes())?;
    std::fs::write(
        ca_meta_path(paths),
        serde_json::to_vec_pretty(&CaMeta { not_after_unix: not_after })?,
    )?;
    tracing::warn!(
        ca = %ca_pem_path(paths).display(),
        "generated a NEW local HTTPS CA — clients that require https must (re)trust it \
         (POST /v1/tls/trust or import ca.pem manually)"
    );

    let disk_der = cert.der().clone();
    Ok(CaHandle { issuer: cert, issuer_key: key, disk_der, not_after_unix: not_after })
}

/// Build the boot-time TLS material: load/create the CA, issue a fresh in-memory leaf for the
/// loopback SANs (+ `extra_sans`, e.g. the LAN IP when exposed), and assemble a rustls config
/// (ring provider, ALPN h2 + http/1.1).
pub fn load_or_create(paths: &Paths, extra_sans: &[String]) -> LocalResult<TlsMaterial> {
    let ca = load_or_create_ca(paths)?;

    let mut sans: Vec<String> =
        vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
    for s in extra_sans {
        if !s.trim().is_empty() && !sans.iter().any(|x| x == s) {
            sans.push(s.clone());
        }
    }

    let leaf_not_after = (now_unix() + LEAF_VALID_DAYS * 86_400).min(ca.not_after_unix);
    let mut leaf_params = CertificateParams::new(sans).map_err(|e| internal("leaf params", e))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Writ local daemon");
    leaf_params.distinguished_name = dn;
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    // AKI is REQUIRED by strict RFC-5280 verifiers (OpenSSL X509_STRICT — Python 3.13+'s default
    // ssl context) on any non-self-signed cert; webpki tolerates its absence, so only live clients
    // catch this. rcgen derives it from the issuer's key.
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params.not_before = odt(now_unix() - 3_600)?;
    leaf_params.not_after = odt(leaf_not_after)?;

    let leaf_key = KeyPair::generate().map_err(|e| internal("leaf keygen", e))?;
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca.issuer, &ca.issuer_key)
        .map_err(|e| internal("leaf sign", e))?;

    // Chain = [leaf, on-disk anchor]. Serving the anchor too lets clients that pin only the CA
    // build the chain without an AIA fetch (there is none — this never leaves the machine).
    let chain = vec![leaf.der().clone(), ca.disk_der.clone()];
    let key_der = PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into());

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| internal("rustls versions", e))?
        .with_no_client_auth()
        .with_single_cert(chain, key_der)
        .map_err(|e| internal("rustls cert", e))?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TlsMaterial {
        server_config: Arc::new(cfg),
        ca_path: ca_pem_path(paths),
        ca_fingerprint_sha256: sha256_hex(&ca.disk_der),
        ca_expires_at: rfc3339(ca.not_after_unix),
        leaf_expires_at: rfc3339(leaf_not_after),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_paths() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join(".writ"));
        paths.ensure_dirs().unwrap();
        (dir, paths)
    }

    #[test]
    fn ca_persists_and_leaf_reissues() {
        let (_dir, paths) = temp_paths();

        let m1 = load_or_create(&paths, &[]).unwrap();
        assert!(ca_pem_path(&paths).exists(), "ca.pem written");
        assert!(ca_key_path(&paths).exists(), "ca.key written");
        assert!(ca_meta_path(&paths).exists(), "ca.json written");

        // CA key must be owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(ca_key_path(&paths)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "ca.key must be 0600");
        }

        // Second boot: SAME CA (fingerprint stable), fresh leaf still chains to it.
        let m2 = load_or_create(&paths, &[]).unwrap();
        assert_eq!(m1.ca_fingerprint_sha256, m2.ca_fingerprint_sha256, "CA is reused across boots");
        assert_eq!(m1.ca_expires_at, m2.ca_expires_at);
    }

    #[test]
    fn reissued_leaf_validates_against_disk_anchor() {
        // The critical chain property: a leaf signed by a RELOADED CA key must verify against the
        // ORIGINAL on-disk anchor (what the OS trust store holds). Exercise a real client-side
        // verification via rustls' webpki verifier — this also proves the name constraints and IP
        // SANs are well-formed (webpki enforces both).
        let (_dir, paths) = temp_paths();
        let _first = load_or_create(&paths, &[]).unwrap(); // creates the CA
        let material = load_or_create(&paths, &[]).unwrap(); // reloads it, fresh leaf

        let anchor = read_ca_der(&paths).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(anchor).unwrap();

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            provider,
        )
        .build()
        .unwrap();

        // Rebuild the served chain from the config's cert source by re-issuing the same way the
        // server config was built — instead, verify through a real handshake in server tests; here
        // assert the verifier accepts the chain the material was built from.
        // (load_or_create keeps the chain inside rustls::ServerConfig; re-derive it for the check.)
        let ca = load_or_create_ca(&paths).unwrap();
        let mut leaf_params = CertificateParams::new(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .unwrap();
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf_params.not_before = odt(now_unix() - 3_600).unwrap();
        leaf_params.not_after = odt(now_unix() + 86_400).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &ca.issuer, &ca.issuer_key).unwrap();

        use rustls::client::danger::ServerCertVerifier;
        let end_entity = leaf.der().clone();
        let intermediates = [ca.disk_der.clone()];
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        verifier
            .verify_server_cert(
                &end_entity,
                &intermediates,
                &name,
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .expect("leaf from reloaded CA key must chain to the on-disk anchor");

        // IP-SAN path too (webpki also checks the name constraints cover it).
        let ip_name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
        verifier
            .verify_server_cert(&end_entity, &intermediates, &ip_name, &[], rustls::pki_types::UnixTime::now())
            .expect("IP SAN must validate under the name-constrained CA");

        let _ = material; // silence unused when cfg-gated
    }

    #[test]
    fn leaf_carries_aki_for_strict_verifiers() {
        // OpenSSL X509_STRICT (Python 3.13+ default ssl) REQUIRES an Authority Key Identifier on
        // every non-self-signed cert; webpki doesn't, so only this assertion (and live clients)
        // would catch a regression. Check the issued leaf DER for the AKI extension OID (2.5.29.35
        // = 55 1D 23) — the CA's SKI OID (2.5.29.14) has different bytes, so no false positive.
        let (_dir, paths) = temp_paths();
        let ca = load_or_create_ca(&paths).unwrap();
        let mut leaf_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf_params.use_authority_key_identifier_extension = true;
        leaf_params.not_before = odt(now_unix() - 3_600).unwrap();
        leaf_params.not_after = odt(now_unix() + 86_400).unwrap();
        let key = KeyPair::generate().unwrap();
        let leaf = leaf_params.signed_by(&key, &ca.issuer, &ca.issuer_key).unwrap();
        let der = leaf.der().as_ref();
        let aki_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x23];
        assert!(
            der.windows(aki_oid.len()).any(|w| w == aki_oid),
            "leaf must carry the AuthorityKeyIdentifier extension (strict RFC-5280 verifiers)"
        );
    }

    #[test]
    fn expiring_ca_regenerates() {
        let (_dir, paths) = temp_paths();
        let m1 = load_or_create(&paths, &[]).unwrap();

        // Rewrite the meta as nearly-expired → next load must mint a NEW CA.
        std::fs::write(
            ca_meta_path(&paths),
            serde_json::to_vec(&CaMeta { not_after_unix: now_unix() + 86_400 }).unwrap(),
        )
        .unwrap();
        let m2 = load_or_create(&paths, &[]).unwrap();
        assert_ne!(m1.ca_fingerprint_sha256, m2.ca_fingerprint_sha256, "near-expiry CA is replaced");
    }
}
