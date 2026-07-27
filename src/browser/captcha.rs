use serde::{Deserialize, Serialize};

/// Known CAPTCHA / challenge types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptchaType {
    RecaptchaV2,
    RecaptchaV3,
    HCaptcha,
    Turnstile,
    CloudflareChallenge,
    Unknown,
}

/// Returns a JavaScript snippet that detects whether the page contains any
/// CAPTCHA challenge.
///
/// The script checks eight CSS selectors for known CAPTCHA widgets and falls
/// back to the page title for Cloudflare interstitials. Returns `true` if a
/// CAPTCHA is found, `false` otherwise.
///
/// Ported from the Python `_detect_captcha` method.
pub fn detect_captcha_js() -> &'static str {
    r#"(() => {
    const selectors = [
        'iframe[src*="recaptcha"]',
        'iframe[src*="hcaptcha"]',
        '[data-sitekey]',
        '.g-recaptcha',
        '.h-captcha',
        '#cf-turnstile',
        '[class*="captcha"]',
        '[id*="captcha"]'
    ];

    for (const sel of selectors) {
        try {
            if (document.querySelector(sel)) return true;
        } catch (e) {}
    }

    // Cloudflare challenge page detection via title
    try {
        const title = document.title || '';
        if (title.includes('Just a moment') || title.includes('Attention Required')) {
            return true;
        }
    } catch (e) {}

    return false;
})()"#
}

/// Returns a JavaScript snippet that identifies the specific CAPTCHA type on
/// the page.
///
/// Returns one of: `"recaptcha_v2"`, `"recaptcha_v3"`, `"hcaptcha"`,
/// `"turnstile"`, `"cloudflare_challenge"`, `"unknown"`, or `null` if no
/// CAPTCHA is detected.
///
/// Ported from the Python `_detect_captcha_type` method.
pub fn detect_captcha_type_js() -> &'static str {
    r#"(() => {
    try {
        // reCAPTCHA
        if (document.querySelector('iframe[src*="recaptcha"], .g-recaptcha, [data-sitekey][class*="recaptcha"]')) {
            // v3 has an invisible badge
            if (document.querySelector('.grecaptcha-badge')) {
                return 'recaptcha_v3';
            }
            return 'recaptcha_v2';
        }

        // hCaptcha
        if (document.querySelector('iframe[src*="hcaptcha"], .h-captcha')) {
            return 'hcaptcha';
        }

        // Cloudflare Turnstile
        if (document.querySelector('#cf-turnstile, [data-turnstile-widget], iframe[src*="challenges.cloudflare.com"]')) {
            return 'turnstile';
        }

        // Cloudflare challenge page (interstitial)
        const title = document.title || '';
        if (title.includes('Just a moment') || title.includes('Attention Required')) {
            return 'cloudflare_challenge';
        }

        // Generic / unknown captcha
        if (document.querySelector('[class*="captcha"], [id*="captcha"]')) {
            return 'unknown';
        }
    } catch (e) {}

    return null;
})()"#
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_js_is_nonempty() {
        assert!(!detect_captcha_js().is_empty());
        assert!(!detect_captcha_type_js().is_empty());
    }

    #[test]
    fn captcha_type_serde_roundtrip() {
        let ct = CaptchaType::Turnstile;
        let json = serde_json::to_string(&ct).unwrap();
        assert_eq!(json, "\"turnstile\"");
        let parsed: CaptchaType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ct);
    }
}
