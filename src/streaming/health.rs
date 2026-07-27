pub const DEFAULT_LOGIN_PATTERNS: &[&str] = &[
    r"/login",
    r"/signin",
    r"/sign-in",
    r"/auth",
    r"/sso",
    r"/oauth",
    r"/session/new",
    r"/accounts/login",
];

const SESSION_EXPIRED_PHRASES: &[&str] = &[
    "session expired",
    "session has expired",
    "please log in",
    "please sign in",
    "your session",
    "login required",
];

pub fn is_on_login_page(url: &str, patterns: &[regex::Regex]) -> bool {
    let url_lower = url.to_lowercase();
    patterns.iter().any(|p| p.is_match(&url_lower))
}

pub fn has_session_expired_text(body_text: &str) -> bool {
    let text_lower = body_text.to_lowercase();
    SESSION_EXPIRED_PHRASES
        .iter()
        .any(|phrase| text_lower.contains(phrase))
}
