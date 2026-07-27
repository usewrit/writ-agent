pub const RECOGNITION_SCORER_JS: &str = include_str!("../../js/recognition_scorer.js");
pub const CLICKABLE_SCORER_JS: &str = include_str!("../../js/clickable_scorer.js");

pub const MIN_RECOGNITION_SCORE: u32 = 40;
pub const MIN_CLICKABLE_SCORE: u32 = 30;

#[derive(Debug, Clone)]
pub struct RecognitionConfig {
    pub label: Option<String>,
    pub placeholder: Option<String>,
    pub field_type: Option<String>,
    pub field_category: Option<String>,
    pub autocomplete: Option<String>,
    pub form_index: Option<usize>,
    pub field_index: Option<usize>,
    pub aria_label: Option<String>,
    pub nearby_text: Option<String>,
    pub tag_name: Option<String>,
    pub element_name: Option<String>,
    pub element_id: Option<String>,
    pub data_attributes: Option<serde_json::Value>,
    pub stable_attributes: Option<serde_json::Value>,
}

impl RecognitionConfig {
    pub fn from_json(value: &serde_json::Value) -> Self {
        Self {
            label: value.get("label").and_then(|v| v.as_str()).map(String::from),
            placeholder: value.get("placeholder").and_then(|v| v.as_str()).map(String::from),
            field_type: value.get("field_type").and_then(|v| v.as_str()).map(String::from),
            field_category: value.get("field_category").and_then(|v| v.as_str()).map(String::from),
            autocomplete: value.get("autocomplete").and_then(|v| v.as_str()).map(String::from),
            form_index: value.get("form_index").and_then(|v| v.as_u64()).map(|v| v as usize),
            field_index: value.get("field_index").and_then(|v| v.as_u64()).map(|v| v as usize),
            aria_label: value.get("aria_label").and_then(|v| v.as_str()).map(String::from),
            nearby_text: value.get("nearby_text").and_then(|v| v.as_str()).map(String::from),
            tag_name: value.get("tag_name").and_then(|v| v.as_str()).map(String::from),
            element_name: value.get("element_name").and_then(|v| v.as_str()).map(String::from),
            element_id: value.get("element_id").and_then(|v| v.as_str()).map(String::from),
            data_attributes: value.get("data_attributes").cloned(),
            stable_attributes: value.get("stable_attributes").cloned(),
        }
    }

    pub fn has_meaningful_criteria(&self) -> bool {
        self.label.is_some()
            || self.placeholder.is_some()
            || self.aria_label.is_some()
            || self.element_id.is_some()
            || self.element_name.is_some()
            || self.field_index.is_some()
    }

    pub fn to_js_args(&self) -> serde_json::Value {
        serde_json::json!({
            "label": self.label,
            "placeholder": self.placeholder,
            "field_type": self.field_type,
            "field_category": self.field_category,
            "autocomplete": self.autocomplete,
            "form_index": self.form_index,
            "field_index": self.field_index,
            "aria_label": self.aria_label,
            "nearby_text": self.nearby_text,
            "tag_name": self.tag_name,
            "element_name": self.element_name,
            "element_id": self.element_id,
            "data_attributes": self.data_attributes,
            "stable_attributes": self.stable_attributes,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ClickableConfig {
    pub text: Option<String>,
    pub aria_label: Option<String>,
    pub nearby_text: Option<String>,
    pub element_id: Option<String>,
    pub element_name: Option<String>,
    pub tag_name: Option<String>,
    pub role: Option<String>,
}

impl ClickableConfig {
    pub fn from_json(value: &serde_json::Value) -> Self {
        let stable = value.get("stableAttributes");
        Self {
            text: value.get("text").and_then(|v| v.as_str()).map(String::from),
            aria_label: value.get("aria_label").and_then(|v| v.as_str()).map(String::from),
            nearby_text: value.get("nearby_text").and_then(|v| v.as_str()).map(String::from),
            element_id: value.get("element_id").and_then(|v| v.as_str()).map(String::from),
            element_name: value.get("element_name").and_then(|v| v.as_str()).map(String::from),
            tag_name: value.get("tag_name").and_then(|v| v.as_str()).map(String::from),
            role: stable.and_then(|s| s.get("role")).and_then(|v| v.as_str()).map(String::from),
        }
    }

    pub fn to_js_args(&self) -> serde_json::Value {
        serde_json::json!({
            "text": self.text,
            "aria_label": self.aria_label,
            "nearby_text": self.nearby_text,
            "element_id": self.element_id,
            "element_name": self.element_name,
            "tag_name": self.tag_name,
            "role": self.role,
        })
    }
}
