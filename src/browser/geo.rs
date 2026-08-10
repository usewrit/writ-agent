//! Browser identity that MATCHES the egress exit country.
//!
//! A residential proxy buys a clean IP; it does not buy a coherent identity. The browser
//! still advertises a timezone, a locale and an Accept-Language, and anti-bot systems
//! compare those against the GeoIP of the connecting address. A US timezone on a Canadian
//! exit is a contradiction no real user produces — a stronger signal than the IP's
//! reputation is a positive one. The exit country is decided per session, so the identity
//! is derived per session; unknown countries fall back to a neutral, self-consistent
//! default rather than guessing.

/// A coherent (locale, timezone, Accept-Language) triple for an exit country.
#[derive(Debug, Clone)]
pub struct GeoIdentity {
    pub locale: String,
    pub timezone: String,
    pub accept_language: String,
    /// Normalized ISO-3166 code actually used ("" when the default was applied).
    pub country: String,
}

// ISO-3166-alpha-2 → (IANA timezone, BCP-47 locale, Accept-Language). One representative
// timezone per country: the goal is COHERENCE with GeoIP, not pinpoint accuracy.
const GEO: &[(&str, &str, &str, &str)] = &[
    // North America
    ("US", "America/New_York", "en-US", "en-US,en;q=0.9"),
    ("CA", "America/Toronto", "en-CA", "en-CA,en;q=0.9,fr-CA;q=0.8"),
    ("MX", "America/Mexico_City", "es-MX", "es-MX,es;q=0.9,en;q=0.8"),
    // Europe
    ("GB", "Europe/London", "en-GB", "en-GB,en;q=0.9"),
    ("IE", "Europe/Dublin", "en-IE", "en-IE,en;q=0.9"),
    ("FR", "Europe/Paris", "fr-FR", "fr-FR,fr;q=0.9,en;q=0.8"),
    ("DE", "Europe/Berlin", "de-DE", "de-DE,de;q=0.9,en;q=0.8"),
    ("ES", "Europe/Madrid", "es-ES", "es-ES,es;q=0.9,en;q=0.8"),
    ("IT", "Europe/Rome", "it-IT", "it-IT,it;q=0.9,en;q=0.8"),
    ("NL", "Europe/Amsterdam", "nl-NL", "nl-NL,nl;q=0.9,en;q=0.8"),
    ("BE", "Europe/Brussels", "nl-BE", "nl-BE,nl;q=0.9,fr-BE;q=0.8,en;q=0.7"),
    ("CH", "Europe/Zurich", "de-CH", "de-CH,de;q=0.9,fr-CH;q=0.8,en;q=0.7"),
    ("AT", "Europe/Vienna", "de-AT", "de-AT,de;q=0.9,en;q=0.8"),
    ("PT", "Europe/Lisbon", "pt-PT", "pt-PT,pt;q=0.9,en;q=0.8"),
    ("PL", "Europe/Warsaw", "pl-PL", "pl-PL,pl;q=0.9,en;q=0.8"),
    ("SE", "Europe/Stockholm", "sv-SE", "sv-SE,sv;q=0.9,en;q=0.8"),
    ("NO", "Europe/Oslo", "nb-NO", "nb-NO,nb;q=0.9,en;q=0.8"),
    ("DK", "Europe/Copenhagen", "da-DK", "da-DK,da;q=0.9,en;q=0.8"),
    ("FI", "Europe/Helsinki", "fi-FI", "fi-FI,fi;q=0.9,en;q=0.8"),
    ("CZ", "Europe/Prague", "cs-CZ", "cs-CZ,cs;q=0.9,en;q=0.8"),
    ("RO", "Europe/Bucharest", "ro-RO", "ro-RO,ro;q=0.9,en;q=0.8"),
    ("GR", "Europe/Athens", "el-GR", "el-GR,el;q=0.9,en;q=0.8"),
    ("UA", "Europe/Kyiv", "uk-UA", "uk-UA,uk;q=0.9,en;q=0.8"),
    ("TR", "Europe/Istanbul", "tr-TR", "tr-TR,tr;q=0.9,en;q=0.8"),
    // Asia-Pacific
    ("AU", "Australia/Sydney", "en-AU", "en-AU,en;q=0.9"),
    ("NZ", "Pacific/Auckland", "en-NZ", "en-NZ,en;q=0.9"),
    ("JP", "Asia/Tokyo", "ja-JP", "ja-JP,ja;q=0.9,en;q=0.8"),
    ("KR", "Asia/Seoul", "ko-KR", "ko-KR,ko;q=0.9,en;q=0.8"),
    ("SG", "Asia/Singapore", "en-SG", "en-SG,en;q=0.9,zh-SG;q=0.8"),
    ("HK", "Asia/Hong_Kong", "zh-HK", "zh-HK,zh;q=0.9,en;q=0.8"),
    ("IN", "Asia/Kolkata", "en-IN", "en-IN,en;q=0.9,hi;q=0.8"),
    ("ID", "Asia/Jakarta", "id-ID", "id-ID,id;q=0.9,en;q=0.8"),
    ("PH", "Asia/Manila", "en-PH", "en-PH,en;q=0.9,fil;q=0.8"),
    ("TH", "Asia/Bangkok", "th-TH", "th-TH,th;q=0.9,en;q=0.8"),
    ("VN", "Asia/Ho_Chi_Minh", "vi-VN", "vi-VN,vi;q=0.9,en;q=0.8"),
    ("IL", "Asia/Jerusalem", "he-IL", "he-IL,he;q=0.9,en;q=0.8"),
    ("AE", "Asia/Dubai", "ar-AE", "ar-AE,ar;q=0.9,en;q=0.8"),
    // Latin America / Africa
    ("BR", "America/Sao_Paulo", "pt-BR", "pt-BR,pt;q=0.9,en;q=0.8"),
    ("AR", "America/Argentina/Buenos_Aires", "es-AR", "es-AR,es;q=0.9,en;q=0.8"),
    ("CL", "America/Santiago", "es-CL", "es-CL,es;q=0.9,en;q=0.8"),
    ("CO", "America/Bogota", "es-CO", "es-CO,es;q=0.9,en;q=0.8"),
    ("ZA", "Africa/Johannesburg", "en-ZA", "en-ZA,en;q=0.9"),
    ("NG", "Africa/Lagos", "en-NG", "en-NG,en;q=0.9"),
    ("EG", "Africa/Cairo", "ar-EG", "ar-EG,ar;q=0.9,en;q=0.8"),
];

// Default: US/en-US — the single most common real-world combination, so the least
// remarkable guess, and self-consistent.
const DEFAULT: (&str, &str, &str) = ("America/New_York", "en-US", "en-US,en;q=0.9");

// Country names / non-ISO tokens providers or operators actually use.
const ALIASES: &[(&str, &str)] = &[
    ("unitedstates", "US"), ("usa", "US"), ("unitedstatesofamerica", "US"),
    ("canada", "CA"), ("unitedkingdom", "GB"), ("greatbritain", "GB"), ("uk", "GB"),
    ("germany", "DE"), ("france", "FR"), ("spain", "ES"), ("italy", "IT"),
    ("netherlands", "NL"), ("australia", "AU"), ("japan", "JP"), ("brazil", "BR"),
    ("india", "IN"), ("mexico", "MX"), ("singapore", "SG"), ("switzerland", "CH"),
    ("sweden", "SE"), ("poland", "PL"), ("ireland", "IE"), ("newzealand", "NZ"),
    ("southafrica", "ZA"), ("southkorea", "KR"), ("hongkong", "HK"),
    ("unitedarabemirates", "AE"), ("uae", "AE"), ("czechia", "CZ"), ("czechrepublic", "CZ"),
];

/// Best-effort ISO-3166-alpha-2 (upper-case) from an alpha-2 code (any case) or a country
/// NAME. Returns None when nothing usable can be derived, so callers fall back.
pub fn normalize_country(country: Option<&str>) -> Option<String> {
    let raw = country?.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.len() == 2 && raw.chars().all(|c| c.is_ascii_alphabetic()) {
        return Some(raw.to_ascii_uppercase());
    }
    let key: String = raw.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect();
    ALIASES.iter().find(|(k, _)| *k == key).map(|(_, v)| v.to_string())
}

/// Coherent browser identity for an egress exit in `country`.
pub fn resolve(country: Option<&str>) -> GeoIdentity {
    let code = normalize_country(country);
    let entry = code
        .as_deref()
        .and_then(|c| GEO.iter().find(|(cc, ..)| *cc == c))
        .map(|(_, tz, loc, langs)| (*tz, *loc, *langs))
        .unwrap_or(DEFAULT);
    GeoIdentity {
        timezone: entry.0.to_string(),
        locale: entry.1.to_string(),
        accept_language: entry.2.to_string(),
        country: code.unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_maps_to_toronto_en_ca() {
        let g = resolve(Some("CA"));
        assert_eq!(g.timezone, "America/Toronto");
        assert_eq!(g.locale, "en-CA");
        assert!(g.accept_language.starts_with("en-CA"));
    }

    #[test]
    fn names_and_aliases() {
        assert_eq!(normalize_country(Some("Canada")).as_deref(), Some("CA"));
        assert_eq!(normalize_country(Some("UnitedStates")).as_deref(), Some("US"));
        assert_eq!(normalize_country(Some("fr")).as_deref(), Some("FR"));
        assert_eq!(normalize_country(Some("")), None);
        assert_eq!(normalize_country(None), None);
    }

    #[test]
    fn unknown_country_is_default() {
        let g = resolve(Some("ZZ"));
        assert_eq!(g.locale, "en-US");
        assert_eq!(g.country, "ZZ");
    }
}
