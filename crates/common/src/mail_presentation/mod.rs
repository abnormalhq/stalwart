// SPDX-License-Identifier: AGPL-3.0-only

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::fmt;

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_INPUT_BYTES: usize = 16 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 32 * 1024;
pub const MAX_PLACEHOLDER_VALUE_BYTES: usize = 2_048;
pub const MAX_PLACEHOLDER_VALUES_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PresentationKind {
    Branding,
    CalendarAlarm,
    Scheduling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PresentationPlaceholder {
    WorkspaceName,
    EventTitle,
    EventDescription,
    EventStart,
    EventEnd,
    Location,
    OrganizerName,
    ChangeSummary,
}

impl PresentationPlaceholder {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "workspaceName" => Some(Self::WorkspaceName),
            "eventTitle" => Some(Self::EventTitle),
            "eventDescription" => Some(Self::EventDescription),
            "eventStart" => Some(Self::EventStart),
            "eventEnd" => Some(Self::EventEnd),
            "location" => Some(Self::Location),
            "organizerName" => Some(Self::OrganizerName),
            "changeSummary" => Some(Self::ChangeSummary),
            _ => None,
        }
    }
}

pub type PresentationValues = BTreeMap<PresentationPlaceholder, String>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationDocument {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: PresentationKind,
    pub sections: PresentationSections,
    pub brand: PresentationBrand,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationSections {
    pub title: String,
    pub intro: String,
    pub footer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationBrand {
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub accent: String,
    #[serde(
        rename = "logoId",
        default,
        deserialize_with = "deserialize_logo_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub logo_id: Option<String>,
}

fn deserialize_logo_id<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationContent {
    pub text: String,
    pub html: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationError {
    InvalidDocument,
    InvalidTemplate,
    UnknownPlaceholder,
    InvalidValue,
    InvalidLogoContentId,
    UnsafeSubject,
    InputTooLarge,
    OutputTooLarge,
}

impl fmt::Display for PresentationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for PresentationError {}

fn allowed_placeholders(kind: PresentationKind) -> &'static [PresentationPlaceholder] {
    match kind {
        PresentationKind::Branding => &[PresentationPlaceholder::WorkspaceName],
        PresentationKind::CalendarAlarm => &[
            PresentationPlaceholder::EventTitle,
            PresentationPlaceholder::EventDescription,
            PresentationPlaceholder::EventStart,
            PresentationPlaceholder::EventEnd,
            PresentationPlaceholder::Location,
            PresentationPlaceholder::OrganizerName,
        ],
        PresentationKind::Scheduling => &[
            PresentationPlaceholder::EventTitle,
            PresentationPlaceholder::EventStart,
            PresentationPlaceholder::EventEnd,
            PresentationPlaceholder::Location,
            PresentationPlaceholder::OrganizerName,
            PresentationPlaceholder::ChangeSummary,
        ],
    }
}

fn is_control_free(value: &str) -> bool {
    !value.chars().any(char::is_control)
}

fn looks_like_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if [
        "://",
        "http:",
        "https:",
        "ftp:",
        "mailto:",
        "data:",
        "javascript:",
        "file:",
        "cid:",
        "www.",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        return true;
    }

    value.split_whitespace().any(|word| {
        let token = word
            .rsplit('@')
            .next()
            .unwrap_or(word)
            .trim_matches(|character: char| {
                !character.is_ascii_alphanumeric() && character != '.' && character != '-'
            })
            .trim_matches('.');
        let labels = token.split('.').collect::<Vec<_>>();
        if labels.len() == 4 && labels.iter().all(|label| label.parse::<u8>().is_ok()) {
            return true;
        }
        if labels.len() < 2 {
            return false;
        }
        let tld = labels[labels.len() - 1];
        tld.len() >= 2
            && tld.bytes().all(|byte| byte.is_ascii_alphabetic())
            && labels.iter().all(|label| {
                !label.is_empty()
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
    })
}

fn validate_template(
    value: &str,
    max_bytes: usize,
    kind: PresentationKind,
) -> Result<(), PresentationError> {
    if value.len() > max_bytes
        || !is_control_free(value)
        || value.contains('<')
        || value.contains('>')
    {
        return Err(PresentationError::InvalidTemplate);
    }
    if looks_like_url(value) {
        return Err(PresentationError::InvalidTemplate);
    }

    let mut remaining = value;
    while let Some(start) = remaining.find("{{") {
        if remaining[..start].contains('{') || remaining[..start].contains('}') {
            return Err(PresentationError::InvalidTemplate);
        }
        let after_open = &remaining[start + 2..];
        let end = after_open
            .find("}}")
            .ok_or(PresentationError::InvalidTemplate)?;
        let name = &after_open[..end];
        if name.is_empty()
            || !name.as_bytes()[0].is_ascii_alphabetic()
            || !name.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(PresentationError::InvalidTemplate);
        }
        let Some(placeholder) = PresentationPlaceholder::from_name(name) else {
            return Err(PresentationError::UnknownPlaceholder);
        };
        if !allowed_placeholders(kind).contains(&placeholder) {
            return Err(PresentationError::UnknownPlaceholder);
        }
        remaining = &after_open[end + 2..];
    }
    if remaining.contains('{') || remaining.contains('}') {
        return Err(PresentationError::InvalidTemplate);
    }
    Ok(())
}

pub fn validate(document: &PresentationDocument) -> Result<(), PresentationError> {
    if document.schema_version != SCHEMA_VERSION
        || document.brand.display_name.trim().is_empty()
        || document.brand.display_name.len() > 100
        || !is_control_free(&document.brand.display_name)
        || document.brand.display_name.contains('<')
        || document.brand.display_name.contains('>')
        || document.brand.display_name.contains('{')
        || document.brand.display_name.contains('}')
        || looks_like_url(&document.brand.display_name)
    {
        return Err(PresentationError::InvalidDocument);
    }
    let accent = document.brand.accent.as_bytes();
    if accent.len() != 7 || accent[0] != b'#' || !accent[1..].iter().all(u8::is_ascii_hexdigit) {
        return Err(PresentationError::InvalidDocument);
    }
    if let Some(logo_id) = &document.brand.logo_id {
        if logo_id.is_empty()
            || logo_id.len() > 64
            || !logo_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(PresentationError::InvalidDocument);
        }
    }
    validate_template(&document.sections.title, 180, document.kind)?;
    validate_template(&document.sections.intro, 1_500, document.kind)?;
    validate_template(&document.sections.footer, 500, document.kind)?;
    Ok(())
}

pub fn parse_profile(value: &str) -> Result<PresentationDocument, PresentationError> {
    if value.len() > MAX_INPUT_BYTES {
        return Err(PresentationError::InputTooLarge);
    }
    let document = serde_json::from_str::<PresentationDocument>(value)
        .map_err(|_| PresentationError::InvalidDocument)?;
    validate(&document)?;
    Ok(document)
}

fn normalize_values(
    kind: PresentationKind,
    values: &PresentationValues,
) -> Result<PresentationValues, PresentationError> {
    let allowed = allowed_placeholders(kind);
    let mut total = 0;
    let mut normalized_values = BTreeMap::new();
    for (name, value) in values {
        if !allowed.contains(name) {
            return Err(PresentationError::InvalidValue);
        }
        let normalized = value.replace("\r\n", "\n");
        if normalized
            .chars()
            .any(|character| character.is_control() && character != '\n')
        {
            return Err(PresentationError::InvalidValue);
        }
        if normalized.len() > MAX_PLACEHOLDER_VALUE_BYTES {
            return Err(PresentationError::InvalidValue);
        }
        total += normalized.len();
        normalized_values.insert(*name, normalized);
    }
    if total > MAX_PLACEHOLDER_VALUES_BYTES {
        return Err(PresentationError::InvalidValue);
    }
    Ok(normalized_values)
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn substitute(template: &str, values: &PresentationValues) -> Result<String, PresentationError> {
    let mut output = String::with_capacity(template.len());
    let mut remaining = template;
    while let Some(start) = remaining.find("{{") {
        output.push_str(&remaining[..start]);
        let after_open = &remaining[start + 2..];
        let end = after_open
            .find("}}")
            .ok_or(PresentationError::InvalidTemplate)?;
        let name = &after_open[..end];
        let placeholder = PresentationPlaceholder::from_name(name)
            .ok_or(PresentationError::UnknownPlaceholder)?;
        if let Some(value) = values.get(&placeholder) {
            output.push_str(value);
        }
        remaining = &after_open[end + 2..];
    }
    output.push_str(remaining);
    Ok(output)
}

pub fn logo_content_id(
    document: &PresentationDocument,
) -> Result<Option<String>, PresentationError> {
    validate(document)?;
    Ok(expected_logo_content_id(document))
}

fn expected_logo_content_id(document: &PresentationDocument) -> Option<String> {
    document
        .brand
        .logo_id
        .as_ref()
        .map(|logo_id| format!("mail-presentation.{logo_id}@abnormal.invalid"))
}

pub fn render(
    document: &PresentationDocument,
    values: &PresentationValues,
    logo_content_id: Option<&str>,
) -> Result<PresentationContent, PresentationError> {
    validate(document)?;
    let values = normalize_values(document.kind, values)?;
    if let Some(content_id) = logo_content_id {
        if expected_logo_content_id(document).as_deref() != Some(content_id) {
            return Err(PresentationError::InvalidLogoContentId);
        }
    }

    let title = substitute(&document.sections.title, &values)?;
    let intro_template = if !values
        .get(&PresentationPlaceholder::EventTitle)
        .is_some_and(|title| !title.trim().is_empty())
    {
        match (document.kind, document.sections.intro.as_str()) {
            (PresentationKind::CalendarAlarm, "You have a reminder for {{eventTitle}}.") => {
                "You have an upcoming event reminder."
            }
            (PresentationKind::Scheduling, "An event has been updated: {{eventTitle}}.") => {
                "A calendar event has been updated."
            }
            _ => document.sections.intro.as_str(),
        }
    } else {
        document.sections.intro.as_str()
    };
    let intro = substitute(intro_template, &values)?;
    let footer = substitute(&document.sections.footer, &values)?;
    let display_name = document.brand.display_name.trim();
    let accent = document.brand.accent.to_ascii_lowercase();
    let text = [
        display_name,
        title.as_str(),
        intro.as_str(),
        footer.as_str(),
    ]
    .into_iter()
    .filter(|section| !section.is_empty())
    .collect::<Vec<_>>()
    .join("\n\n");

    let logo = logo_content_id
        .map(|content_id| {
            format!(
                "<img src=\"cid:{}\" alt=\"{}\" style=\"display:block;max-width:160px;max-height:64px;margin:0 0 20px\">",
                escape_html(content_id),
                escape_html(display_name)
            )
        })
        .unwrap_or_default();
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"></head><body style=\"margin:0;background:#f4f5f7;font-family:Arial,sans-serif;color:#20242c\"><main style=\"max-width:600px;margin:24px auto;padding:32px;background:#fff;border-top:4px solid {}\">{}<p style=\"margin:0 0 24px;color:{};font-size:14px;font-weight:700\">{}</p><h1 style=\"margin:0 0 16px;font-size:24px;line-height:1.3\">{}</h1><p style=\"margin:0 0 24px;white-space:pre-wrap;line-height:1.6\">{}</p><p style=\"margin:0;color:#606875;font-size:13px;white-space:pre-wrap\">{}</p></main></body></html>",
        accent,
        logo,
        accent,
        escape_html(display_name),
        escape_html(&title),
        escape_html(&intro),
        escape_html(&footer)
    );
    if text.len() > MAX_OUTPUT_BYTES || html.len() > MAX_OUTPUT_BYTES {
        return Err(PresentationError::OutputTooLarge);
    }
    Ok(PresentationContent { text, html })
}

pub fn fallback(kind: PresentationKind) -> PresentationDocument {
    let (title, intro, footer) = match kind {
        PresentationKind::Branding => (
            "Abnormal Mail",
            "Secure email for your workspace.",
            "Sent with Abnormal Mail.",
        ),
        PresentationKind::CalendarAlarm => (
            "Upcoming event reminder",
            "You have a reminder for {{eventTitle}}.",
            "Sent with Abnormal Mail.",
        ),
        PresentationKind::Scheduling => (
            "Calendar update",
            "An event has been updated: {{eventTitle}}.",
            "Sent with Abnormal Mail.",
        ),
    };
    PresentationDocument {
        schema_version: SCHEMA_VERSION,
        kind,
        sections: PresentationSections {
            title: title.to_string(),
            intro: intro.to_string(),
            footer: footer.to_string(),
        },
        brand: PresentationBrand {
            display_name: "Abnormal Mail".to_string(),
            accent: "#3659e3".to_string(),
            logo_id: None,
        },
    }
}

fn fallback_values(kind: PresentationKind, values: &PresentationValues) -> PresentationValues {
    let mut placeholders = allowed_placeholders(kind).to_vec();
    if let Some(index) = placeholders
        .iter()
        .position(|placeholder| *placeholder == PresentationPlaceholder::EventTitle)
    {
        placeholders.remove(index);
        placeholders.insert(0, PresentationPlaceholder::EventTitle);
    }
    let mut safe_values = BTreeMap::new();
    let mut total_bytes = 0;
    for placeholder in placeholders {
        let Some(value) = values.get(&placeholder) else {
            continue;
        };
        if total_bytes + value.len() > MAX_PLACEHOLDER_VALUES_BYTES {
            continue;
        }
        let candidate = BTreeMap::from([(placeholder, value.clone())]);
        if let Ok(normalized) = normalize_values(kind, &candidate) {
            if let Some(normalized_value) = normalized.get(&placeholder) {
                total_bytes += normalized_value.len();
                safe_values.insert(placeholder, normalized_value.clone());
            }
        }
    }
    safe_values
}

fn fallback_for_values(
    kind: PresentationKind,
    values: &PresentationValues,
) -> PresentationDocument {
    let mut document = fallback(kind);
    if values
        .get(&PresentationPlaceholder::EventTitle)
        .is_some_and(|title| !title.trim().is_empty())
    {
        document.sections.intro = match kind {
            PresentationKind::CalendarAlarm => "You have a reminder for {{eventTitle}}.",
            PresentationKind::Scheduling => "An event has been updated: {{eventTitle}}.",
            PresentationKind::Branding => return document,
        }
        .to_string();
    } else {
        document.sections.intro = match kind {
            PresentationKind::CalendarAlarm => "You have an upcoming event reminder.",
            PresentationKind::Scheduling => "A calendar event has been updated.",
            PresentationKind::Branding => return document,
        }
        .to_string();
    }
    document
}

fn static_safe_fallback() -> PresentationContent {
    PresentationContent {
        text: "Abnormal Mail\n\nCalendar event notification\n\nYou have an upcoming event reminder.\n\nSent with Abnormal Mail.".to_string(),
        html: "<!doctype html><html><head><meta charset=\"utf-8\"></head><body style=\"margin:0;background:#f4f5f7;font-family:Arial,sans-serif;color:#20242c\"><main style=\"max-width:600px;margin:24px auto;padding:32px;background:#fff;border-top:4px solid #3659e3\"><p style=\"margin:0 0 24px;color:#3659e3;font-size:14px;font-weight:700\">Abnormal Mail</p><h1 style=\"margin:0 0 16px;font-size:24px;line-height:1.3\">Calendar event notification</h1><p style=\"margin:0 0 24px;white-space:pre-wrap;line-height:1.6\">You have an upcoming event reminder.</p><p style=\"margin:0;color:#606875;font-size:13px;white-space:pre-wrap\">Sent with Abnormal Mail.</p></main></body></html>".to_string(),
    }
}

pub fn render_or_fallback(
    document: &PresentationDocument,
    values: &PresentationValues,
    logo_content_id: Option<&str>,
) -> PresentationContent {
    render(document, values, logo_content_id).unwrap_or_else(|_| {
        let safe_values = fallback_values(document.kind, values);
        let fallback = fallback_for_values(document.kind, &safe_values);
        render(&fallback, &safe_values, None).unwrap_or_else(|_| static_safe_fallback())
    })
}

pub fn render_json_or_fallback(
    kind: PresentationKind,
    input: &str,
    values: &PresentationValues,
    logo_content_id: Option<&str>,
) -> PresentationContent {
    match parse_profile(input) {
        Ok(document) if document.kind == kind => {
            render_or_fallback(&document, values, logo_content_id)
        }
        _ => {
            let safe_values = fallback_values(kind, values);
            let fallback = fallback_for_values(kind, &safe_values);
            render(&fallback, &safe_values, None).unwrap_or_else(|_| static_safe_fallback())
        }
    }
}

pub fn validate_subject(subject: &str) -> Result<(), PresentationError> {
    if subject.len() > 255 || !is_control_free(subject) {
        return Err(PresentationError::UnsafeSubject);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(kind: PresentationKind) -> PresentationDocument {
        PresentationDocument {
            schema_version: SCHEMA_VERSION,
            kind,
            sections: PresentationSections {
                title: "Reminder: {{eventTitle}}".to_string(),
                intro: "<not allowed in templates>".to_string(),
                footer: "Sent with Abnormal Mail.".to_string(),
            },
            brand: PresentationBrand {
                display_name: "Abnormal Mail".to_string(),
                accent: "#3659e3".to_string(),
                logo_id: None,
            },
        }
    }

    #[test]
    fn rejects_html_url_and_unknown_placeholders() {
        let mut value = document(PresentationKind::CalendarAlarm);
        assert_eq!(validate(&value), Err(PresentationError::InvalidTemplate));
        value.sections.intro = "Visit https://example.invalid".to_string();
        assert_eq!(validate(&value), Err(PresentationError::InvalidTemplate));
        value.sections.intro = "Visit example.invalid.".to_string();
        assert_eq!(validate(&value), Err(PresentationError::InvalidTemplate));
        value.sections.intro = "Contact person@example.invalid".to_string();
        assert_eq!(validate(&value), Err(PresentationError::InvalidTemplate));
        value.sections.intro = "{{recipientAddress}}".to_string();
        assert_eq!(validate(&value), Err(PresentationError::UnknownPlaceholder));
    }

    #[test]
    fn rejects_unknown_json_properties_and_controls() {
        let mut value = fallback(PresentationKind::Branding);
        value.sections.title = "Hello\r\nBcc: victim@example.invalid".to_string();
        assert_eq!(validate(&value), Err(PresentationError::InvalidTemplate));

        let json = r##"{"schemaVersion":1,"kind":"branding","sections":{"title":"","intro":"","footer":""},"brand":{"displayName":"Abnormal Mail","accent":"#3659e3"},"subject":"unexpected"}"##;
        assert_eq!(parse_profile(json), Err(PresentationError::InvalidDocument));
        let null_logo = r##"{"schemaVersion":1,"kind":"branding","sections":{"title":"","intro":"","footer":""},"brand":{"displayName":"Abnormal Mail","accent":"#3659e3","logoId":null}}"##;
        assert_eq!(
            parse_profile(null_logo),
            Err(PresentationError::InvalidDocument)
        );
    }

    #[test]
    fn escapes_placeholder_values_and_renders_only_presentation_fields() {
        let mut value = fallback(PresentationKind::CalendarAlarm);
        value.sections.intro = "Reminder for {{eventTitle}}".to_string();
        let values = BTreeMap::from([(
            PresentationPlaceholder::EventTitle,
            "<img src=x onerror=alert(1)>".to_string(),
        )]);
        let rendered = render(&value, &values, None).unwrap();
        assert!(rendered.html.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(!rendered.html.contains("<img src=x onerror"));
        assert!(!rendered.text.contains("Subject:"));
        assert!(!rendered.html.contains("http://"));
    }

    #[test]
    fn enforces_input_output_value_and_subject_bounds() {
        let too_large = " ".repeat(MAX_INPUT_BYTES + 1);
        assert_eq!(
            parse_profile(&too_large),
            Err(PresentationError::InputTooLarge)
        );

        let value = fallback(PresentationKind::Branding);
        let values = BTreeMap::from([(
            PresentationPlaceholder::WorkspaceName,
            "x".repeat(MAX_PLACEHOLDER_VALUE_BYTES + 1),
        )]);
        assert_eq!(
            render(&value, &values, None),
            Err(PresentationError::InvalidValue)
        );
        assert_eq!(
            validate_subject("safe\r\nBcc: x@example.invalid"),
            Err(PresentationError::UnsafeSubject)
        );
        assert!(render(&value, &BTreeMap::new(), None).unwrap().html.len() <= MAX_OUTPUT_BYTES);
    }

    #[test]
    fn caps_escaped_output_and_falls_back_instead_of_returning_an_oversized_rendering() {
        let mut value = fallback(PresentationKind::CalendarAlarm);
        value.sections.intro = "{{eventTitle}}".repeat(4);
        let values = BTreeMap::from([(
            PresentationPlaceholder::EventTitle,
            "&".repeat(MAX_PLACEHOLDER_VALUE_BYTES),
        )]);
        assert_eq!(
            render(&value, &values, None),
            Err(PresentationError::OutputTooLarge)
        );
        let rendered = render_or_fallback(&value, &values, None);
        assert!(rendered.html.len() <= MAX_OUTPUT_BYTES);
        assert_eq!(
            rendered.html.matches("&amp;").count(),
            MAX_PLACEHOLDER_VALUE_BYTES
        );
    }

    #[test]
    fn uses_fallback_when_profile_is_invalid_and_supports_empty_sections() {
        let rendered =
            render_json_or_fallback(PresentationKind::Scheduling, "{}", &BTreeMap::new(), None);
        assert!(rendered.text.contains("Abnormal Mail"));

        let mut empty = fallback(PresentationKind::Branding);
        empty.sections = PresentationSections {
            title: String::new(),
            intro: String::new(),
            footer: String::new(),
        };
        assert!(
            !render(&empty, &BTreeMap::new(), None)
                .unwrap()
                .text
                .is_empty()
        );
    }

    #[test]
    fn fallback_preserves_valid_titles_and_drops_invalid_values() {
        let values = BTreeMap::from([
            (
                PresentationPlaceholder::EventTitle,
                "Quarterly review".to_string(),
            ),
            (
                PresentationPlaceholder::WorkspaceName,
                "not allowed for calendar".to_string(),
            ),
        ]);
        let rendered =
            render_json_or_fallback(PresentationKind::CalendarAlarm, "{}", &values, None);
        assert!(rendered.text.contains("Quarterly review"));
        assert!(!rendered.text.contains("not allowed"));
    }

    #[test]
    fn fallback_preserves_event_title_when_profile_logo_is_invalid() {
        let mut document = fallback(PresentationKind::CalendarAlarm);
        document.brand.logo_id = Some("https://example.invalid/logo.jpg".to_string());
        let values = BTreeMap::from([(
            PresentationPlaceholder::EventTitle,
            "Quarterly review".to_string(),
        )]);

        let rendered = render_or_fallback(&document, &values, None);

        assert!(rendered.text.contains("Quarterly review"));
        assert!(
            rendered
                .text
                .contains("You have a reminder for Quarterly review.")
        );
    }

    #[test]
    fn fallback_without_a_valid_title_uses_complete_generic_intros() {
        let empty = render_json_or_fallback(
            PresentationKind::CalendarAlarm,
            "{}",
            &BTreeMap::new(),
            None,
        );
        assert!(empty.text.contains("You have an upcoming event reminder."));

        let oversized = BTreeMap::from([(
            PresentationPlaceholder::EventTitle,
            "x".repeat(MAX_PLACEHOLDER_VALUE_BYTES + 1),
        )]);
        let rendered =
            render_json_or_fallback(PresentationKind::Scheduling, "{}", &oversized, None);
        assert!(rendered.text.contains("A calendar event has been updated."));
        assert!(
            !rendered
                .text
                .contains(&"x".repeat(MAX_PLACEHOLDER_VALUE_BYTES + 1))
        );
    }

    #[test]
    fn normalizes_body_crlf_values_and_rejects_other_controls() {
        let document = fallback(PresentationKind::CalendarAlarm);
        let values = BTreeMap::from([(
            PresentationPlaceholder::EventTitle,
            "First line\r\nSecond line".to_string(),
        )]);
        let rendered = render(&document, &values, None).unwrap();
        assert!(rendered.text.contains("First line\nSecond line"));
        assert!(!rendered.text.contains('\r'));

        for invalid in ["First\rSecond", "First\tSecond"] {
            let values =
                BTreeMap::from([(PresentationPlaceholder::EventTitle, invalid.to_string())]);
            assert_eq!(
                render(&document, &values, None),
                Err(PresentationError::InvalidValue)
            );
        }
        assert_eq!(
            validate_subject("safe\r\nBcc: injected@example.invalid"),
            Err(PresentationError::UnsafeSubject)
        );
    }

    #[test]
    fn normalizes_lf_and_crlf_event_descriptions_while_preserving_title() {
        let mut document = fallback(PresentationKind::CalendarAlarm);
        document.sections.intro = "{{eventTitle}} {{eventDescription}}".to_string();

        for description in ["First line\nSecond line", "First line\r\nSecond line"] {
            let values = BTreeMap::from([
                (
                    PresentationPlaceholder::EventTitle,
                    "Quarterly review".to_string(),
                ),
                (
                    PresentationPlaceholder::EventDescription,
                    description.to_string(),
                ),
            ]);
            let rendered = render(&document, &values, None).unwrap();

            assert!(rendered.text.contains("Quarterly review"));
            assert!(rendered.text.contains("First line\nSecond line"));
            assert!(!rendered.text.contains('\r'));
        }
    }

    #[test]
    fn only_accepts_renderer_generated_logo_cids() {
        let mut value = fallback(PresentationKind::Branding);
        value.brand.logo_id = Some("logo_01".to_string());
        assert_eq!(
            render(
                &value,
                &BTreeMap::new(),
                Some("https://example.invalid/logo.png")
            ),
            Err(PresentationError::InvalidLogoContentId)
        );
        assert_eq!(
            logo_content_id(&value).unwrap().as_deref(),
            Some("mail-presentation.logo_01@abnormal.invalid")
        );
        let rendered = render(
            &value,
            &BTreeMap::new(),
            Some("mail-presentation.logo_01@abnormal.invalid"),
        )
        .unwrap();
        assert!(
            rendered
                .html
                .contains("src=\"cid:mail-presentation.logo_01@abnormal.invalid\"")
        );
    }
}
