use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessibilityTree {
    #[serde(default)]
    pub tree: serde_json::Value,
    #[serde(default, rename = "pageText")]
    pub page_text: Vec<PageTextSection>,
    #[serde(default)]
    pub errors: Vec<ValidationError>,
    #[serde(default)]
    pub toasts: Vec<ToastMessage>,
    #[serde(default)]
    pub iframes: Vec<IframeInfo>,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub viewport: ViewportInfo,
    #[serde(default, rename = "scrollPosition")]
    pub scroll_position: ScrollPosition,
    #[serde(default, rename = "scrollHeight")]
    pub scroll_height: u32,
    #[serde(default, rename = "hasMoreBelow")]
    pub has_more_below: bool,
    #[serde(default, rename = "hasMoreAbove")]
    pub has_more_above: bool,
    #[serde(default)]
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageTextSection {
    #[serde(rename = "type")]
    pub text_type: String,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "inViewport")]
    pub in_viewport: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    #[serde(skip_serializing_if = "Option::is_none", rename = "fieldIndex")]
    pub field_index: Option<usize>,
    pub field: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub error_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToastMessage {
    pub message: String,
    #[serde(rename = "type")]
    pub toast_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IframeInfo {
    pub index: usize,
    pub purpose: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src: Option<String>,
    pub x: f64,
    pub y: f64,
    #[serde(default)]
    pub width: f64,
    #[serde(default)]
    pub height: f64,
    #[serde(default, rename = "inViewport")]
    pub in_viewport: bool,
    #[serde(default, rename = "crossOrigin")]
    pub cross_origin: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ViewportInfo {
    #[serde(default)]
    pub width: u32,
    #[serde(default)]
    pub height: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScrollPosition {
    #[serde(default)]
    pub x: i32,
    #[serde(default)]
    pub y: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageContext {
    #[serde(default, rename = "pageText")]
    pub page_text: Vec<PageTextSection>,
    #[serde(default)]
    pub errors: Vec<ValidationError>,
    #[serde(default)]
    pub toasts: Vec<ToastMessage>,
    #[serde(default, rename = "fieldValues")]
    pub field_values: HashMap<String, FieldValue>,
    #[serde(default)]
    pub iframes: Vec<IframeInfo>,
    #[serde(default, rename = "hasMoreBelow")]
    pub has_more_below: bool,
    #[serde(default, rename = "hasMoreAbove")]
    pub has_more_above: bool,
    #[serde(default, rename = "scrollPosition")]
    pub scroll_position: ScrollPosition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldValue {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expanded: Option<bool>,
    #[serde(default)]
    pub filled: bool,
}

#[derive(Debug, Clone)]
pub struct DOMSnapshot {
    pub field_signatures: HashMap<usize, String>,
    pub field_values: HashMap<usize, String>,
    pub field_labels: HashMap<usize, String>,
    pub button_texts: Vec<String>,
    pub error_messages: Vec<String>,
    pub toast_messages: Vec<String>,
    pub page_text_hashes: Vec<String>,
    pub url: String,
    pub has_success: bool,
    pub scroll_y: i32,
    pub field_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DOMDiff {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields_added: Vec<FieldChange>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields_removed: Vec<FieldChange>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields_changed: Vec<FieldValueChange>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub field_count_change: i32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub buttons_appeared: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub buttons_disappeared: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors_appeared: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors_cleared: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub toasts_appeared: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_changed: Option<UrlChange>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub success_detected: bool,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub scrolled: i32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub new_text_appeared: Vec<String>,
}

fn is_zero(v: &i32) -> bool {
    *v == 0
}

impl DOMDiff {
    pub fn is_empty(&self) -> bool {
        self.fields_added.is_empty()
            && self.fields_removed.is_empty()
            && self.fields_changed.is_empty()
            && self.field_count_change == 0
            && self.buttons_appeared.is_empty()
            && self.buttons_disappeared.is_empty()
            && self.errors_appeared.is_empty()
            && self.errors_cleared.is_empty()
            && self.toasts_appeared.is_empty()
            && self.url_changed.is_none()
            && !self.success_detected
            && self.scrolled == 0
            && self.new_text_appeared.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldChange {
    pub index: usize,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldValueChange {
    pub index: usize,
    pub before: String,
    pub after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlChange {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DOMFieldInfo {
    pub index: usize,
    #[serde(rename = "type")]
    pub field_type: String,
    pub label: String,
    pub x: f64,
    pub y: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default, rename = "isCheckable")]
    pub is_checkable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default)]
    pub options: Vec<SelectOption>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectOption {
    pub value: String,
    pub text: String,
    #[serde(default)]
    pub selected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DOMState {
    #[serde(default)]
    pub fields: Vec<DOMFieldInfo>,
    #[serde(default)]
    pub buttons: Vec<ButtonInfo>,
    #[serde(default)]
    pub has_success: bool,
    #[serde(default)]
    pub has_error: bool,
    #[serde(default)]
    pub has_captcha: bool,
    #[serde(default)]
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captcha_info: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ButtonInfo {
    pub text: String,
    pub x: f64,
    pub y: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub button_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldInspection {
    pub index: usize,
    pub tag: String,
    #[serde(rename = "type")]
    pub field_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub visible: bool,
    #[serde(rename = "inViewport")]
    pub in_viewport: bool,
    pub coordinates: super::step::Coordinates,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default)]
    pub checked: bool,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub required: bool,
    #[serde(default, rename = "readOnly")]
    pub read_only: bool,
    #[serde(default)]
    pub focused: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "ariaLabel")]
    pub aria_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "validationMessage")]
    pub validation_message: Option<String>,
    #[serde(default)]
    pub options: Vec<SelectOption>,
}
