/// Convert a human-readable label to a snake_case key.
///
/// "First Name" -> "first_name"
/// "E-mail Address!!" -> "e_mail_address"
pub fn label_to_key(label: &str) -> String {
    let lower = label.to_lowercase();

    // Replace any non-alphanumeric character with underscore
    let replaced: String = lower
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();

    // Collapse multiple underscores into one, then trim leading/trailing
    let mut result = String::with_capacity(replaced.len());
    let mut prev_underscore = true; // start true to trim leading
    for c in replaced.chars() {
        if c == '_' {
            if !prev_underscore {
                result.push('_');
            }
            prev_underscore = true;
        } else {
            result.push(c);
            prev_underscore = false;
        }
    }

    // Trim trailing underscore
    if result.ends_with('_') {
        result.pop();
    }

    result
}

/// Generate a realistic placeholder value based on the field type, label, and data key.
///
/// Uses heuristics on the label and type to return sensible sample data.
pub fn generate_placeholder_value(field_type: &str, label: &str, data_key: &str) -> String {
    let label_lower = label.to_lowercase();
    let key_lower = data_key.to_lowercase();
    let type_lower = field_type.to_lowercase();

    // Email
    if type_lower == "email"
        || label_lower.contains("email")
        || label_lower.contains("e-mail")
        || key_lower.contains("email")
    {
        return "user@example.com".to_string();
    }

    // Phone / tel
    if type_lower == "tel"
        || label_lower.contains("phone")
        || label_lower.contains("mobile")
        || label_lower.contains("telephone")
        || key_lower.contains("phone")
    {
        return "(555) 123-4567".to_string();
    }

    // Password
    if type_lower == "password"
        || label_lower.contains("password")
        || key_lower.contains("password")
    {
        return "SecurePass123!".to_string();
    }

    // URL
    if type_lower == "url"
        || label_lower.contains("website")
        || label_lower.contains("url")
        || key_lower.contains("url")
    {
        return "https://www.example.com".to_string();
    }

    // Date
    if type_lower == "date"
        || label_lower.contains("date")
        || label_lower.contains("birthday")
        || label_lower.contains("dob")
        || key_lower.contains("date")
    {
        return "2000-01-15".to_string();
    }

    // First name
    if label_lower.contains("first name")
        || label_lower == "first"
        || key_lower == "first_name"
        || key_lower == "firstname"
    {
        return "John".to_string();
    }

    // Last name
    if label_lower.contains("last name")
        || label_lower == "last"
        || label_lower.contains("surname")
        || key_lower == "last_name"
        || key_lower == "lastname"
    {
        return "Smith".to_string();
    }

    // Full name (check after first/last)
    if label_lower.contains("name") || key_lower.contains("name") {
        return "John Smith".to_string();
    }

    // Address
    if label_lower.contains("address")
        || label_lower.contains("street")
        || key_lower.contains("address")
    {
        return "123 Main Street".to_string();
    }

    // City
    if label_lower.contains("city") || key_lower.contains("city") {
        return "New York".to_string();
    }

    // State
    if label_lower.contains("state") || label_lower.contains("province") || key_lower == "state" {
        return "NY".to_string();
    }

    // Zip / postal code
    if label_lower.contains("zip")
        || label_lower.contains("postal")
        || key_lower.contains("zip")
        || key_lower.contains("postal")
    {
        return "10001".to_string();
    }

    // Country
    if label_lower.contains("country") || key_lower.contains("country") {
        return "United States".to_string();
    }

    // Company / organization
    if label_lower.contains("company")
        || label_lower.contains("organization")
        || label_lower.contains("organisation")
        || key_lower.contains("company")
    {
        return "Acme Inc.".to_string();
    }

    // Message / comment / description
    if label_lower.contains("message")
        || label_lower.contains("comment")
        || label_lower.contains("description")
        || label_lower.contains("notes")
        || type_lower == "textarea"
        || key_lower.contains("message")
    {
        return "This is a sample message for testing purposes.".to_string();
    }

    // Select / dropdown
    if type_lower == "select" {
        return "".to_string(); // leave empty; caller should pick from options
    }

    // Number
    if type_lower == "number" || key_lower.contains("quantity") || key_lower.contains("amount") {
        return "1".to_string();
    }

    // Default
    "Sample Text".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_to_key_basic() {
        assert_eq!(label_to_key("First Name"), "first_name");
    }

    #[test]
    fn test_label_to_key_special_chars() {
        assert_eq!(label_to_key("E-mail Address!!"), "e_mail_address");
    }

    #[test]
    fn test_label_to_key_leading_trailing() {
        assert_eq!(label_to_key("  Hello World  "), "hello_world");
    }

    #[test]
    fn test_label_to_key_multiple_underscores() {
        assert_eq!(label_to_key("a---b___c"), "a_b_c");
    }

    #[test]
    fn test_placeholder_email() {
        let v = generate_placeholder_value("email", "Email Address", "email");
        assert_eq!(v, "user@example.com");
    }

    #[test]
    fn test_placeholder_phone() {
        let v = generate_placeholder_value("tel", "Phone", "phone");
        assert_eq!(v, "(555) 123-4567");
    }

    #[test]
    fn test_placeholder_default() {
        let v = generate_placeholder_value("text", "Unknown Field", "unknown");
        assert_eq!(v, "Sample Text");
    }

    #[test]
    fn test_placeholder_company() {
        let v = generate_placeholder_value("text", "Company", "company");
        assert_eq!(v, "Acme Inc.");
    }
}
