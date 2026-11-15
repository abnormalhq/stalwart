/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Hostname, SpamFilterContext, TextPart,
    analysis::{contains_ignore_ascii_case, starts_with_ignore_ascii_case, to_lowercase_cow},
    modules::html::*,
};
use common::Server;
use hyper::Uri;
use nlp::tokenizers::types::{TokenType, TypesTokenizer};
use std::{borrow::Cow, future::Future};

use super::image_size::ImageSize;

pub trait SpamFilterAnalyzeHtml: Sync + Send {
    fn spam_filter_analyze_html(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

#[derive(Debug)]
struct Href<'x> {
    url_parsed: Option<Cow<'x, Uri>>,
    host: Option<Cow<'x, Hostname>>,
}

impl SpamFilterAnalyzeHtml for Server {
    async fn spam_filter_analyze_html(&self, ctx: &mut SpamFilterContext<'_>) {
        SpamFilterContext::analyze_html(ctx);
    }
}

impl SpamFilterContext<'_> {
    pub fn analyze_html(ctx: &mut Self) {
        // Message only has text/html MIME parts
        if ctx.input.message.content_type().is_some_and(|ct| {
            ct.ctype().eq_ignore_ascii_case("text")
                && ct
                    .subtype()
                    .unwrap_or_default()
                    .eq_ignore_ascii_case("html")
        }) {
            ctx.result.add_tag("MIME_HTML_ONLY");
        }

        for (part_id, part) in ctx.output.text_parts.iter().enumerate() {
            let is_body_part = ctx.input.is_body(part_id as u32);

            let (html_tokens, tokens) = if let TextPart::Html {
                html_tokens,
                tokens,
                ..
            } = part
            {
                (html_tokens, tokens)
            } else {
                continue;
            };

            let mut has_link_to_img = false;
            let mut last_href: Option<Href> = None;
            let mut html_img_words = 0u64;
            let mut in_head: i32 = 0;
            let mut in_body: i32 = 0;

            for token in html_tokens {
                match token {
                    HtmlToken::StartTag {
                        name,
                        attributes,
                        is_self_closing,
                    } => match *name {
                        A => {
                            if let Some(attr) = attributes.iter().find_map(|(attr, value)| {
                                if *attr == HREF {
                                    value.as_deref()
                                } else {
                                    None
                                }
                            }) {
                                let url = to_lowercase_cow(attr.trim());
                                let href = if let Some(parsed) = ctx
                                    .output
                                    .urls
                                    .get(url.as_ref())
                                    .and_then(|url| url.element.url_parsed.as_ref())
                                {
                                    Href {
                                        url_parsed: Some(Cow::Borrowed(&parsed.parts)),
                                        host: Some(Cow::Borrowed(&parsed.host)),
                                    }
                                } else {
                                    let url_parsed = url.parse::<Uri>().ok();
                                    Href {
                                        host: url_parsed.as_ref().and_then(|uri| {
                                            uri.host().map(|host| Cow::Owned(Hostname::new(host)))
                                        }),
                                        url_parsed: url_parsed.map(Cow::Owned),
                                    }
                                };

                                if is_body_part
                                    && attr.starts_with("data:")
                                    && attr.contains(";base64,")
                                {
                                    // Has Data URI encoding
                                    ctx.result.add_tag("HAS_DATA_URI");
                                    if attr.contains("text/") {
                                        //  Uses Data URI encoding to obfuscate plain or HTML in base64
                                        ctx.result.add_tag("DATA_URI_OBFU");
                                    }
                                } else if href.host.as_ref().is_some_and(|h| h.ip.is_some()) {
                                    // HTML anchor points to an IP address
                                    ctx.result.add_tag("HTTP_TO_IP");
                                }

                                if !*is_self_closing {
                                    last_href = Some(href);
                                }
                            }
                        }
                        IMG if is_body_part => {
                            // Duplicate HTML attributes use their first occurrence, as in
                            // HTML parsing. Inline CSS takes precedence inside ImageSize.
                            let value = |name| {
                                attributes
                                    .iter()
                                    .find(|(attr, _)| *attr == name)
                                    .and_then(|(_, value)| value.as_deref())
                            };
                            let size = ImageSize::new(value(WIDTH), value(HEIGHT), value(STYLE));

                            for (attr, value) in attributes {
                                if let Some(value) =
                                    value.as_deref().map(|v| v.trim()).filter(|v| !v.is_empty())
                                {
                                    match *attr {
                                        SRC => {
                                            if starts_with_ignore_ascii_case(value, "data:")
                                                && contains_ignore_ascii_case(value, ";base64,")
                                            {
                                                // Has Data URI encoding
                                                ctx.result.add_tag("HAS_DATA_URI");
                                            } else if starts_with_ignore_ascii_case(
                                                value, "https://",
                                            ) || starts_with_ignore_ascii_case(
                                                value, "http://",
                                            ) {
                                                // Has external image
                                                ctx.result.add_tag("HAS_EXTERNAL_IMG");
                                            }
                                        }
                                        _ => (),
                                    }
                                }
                            }

                            if last_href.is_some() {
                                if size.is_large() {
                                    ctx.result.add_tag("HAS_LINK_TO_LARGE_IMG");
                                    has_link_to_img = true;
                                } else {
                                    ctx.result.add_tag("HAS_LINK_TO_IMG");
                                }
                            }

                            html_img_words = html_img_words.saturating_add(size.word_weight());
                        }
                        META => {
                            let mut has_equiv_refresh = false;
                            let mut has_content_url = false;

                            for (attr, value) in attributes {
                                if let Some(value) =
                                    value.as_deref().map(|v| v.trim()).filter(|v| !v.is_empty())
                                {
                                    if *attr == HTTP_EQUIV {
                                        if value.eq_ignore_ascii_case("refresh") {
                                            has_equiv_refresh = true;
                                        }
                                    } else if *attr == CONTENT
                                        && contains_ignore_ascii_case(value, "url=")
                                    {
                                        has_content_url = true;
                                    }
                                }
                            }

                            if has_equiv_refresh && has_content_url {
                                // HTML meta refresh tag
                                ctx.result.add_tag("HTML_META_REFRESH_URL");
                            }
                        }
                        LINK if is_body_part => {
                            let mut has_rel_style = false;
                            let mut has_href_css = false;

                            for (attr, value) in attributes {
                                if let Some(value) =
                                    value.as_deref().map(|v| v.trim()).filter(|v| !v.is_empty())
                                {
                                    if *attr == REL {
                                        if contains_ignore_ascii_case(value, "stylesheet") {
                                            has_rel_style = true;
                                        }
                                    } else if *attr == HREF
                                        && contains_ignore_ascii_case(value, ".css")
                                    {
                                        has_href_css = true;
                                    }
                                }
                            }

                            if has_rel_style || has_href_css {
                                // Has external CSS
                                ctx.result.add_tag("EXT_CSS");
                            }
                        }
                        HEAD if !*is_self_closing => {
                            in_head += 1;
                        }
                        BODY if !*is_self_closing => {
                            in_body += 1;
                        }
                        _ => {}
                    },
                    HtmlToken::EndTag { name } => match *name {
                        A => {
                            last_href = None;
                        }
                        HEAD => {
                            in_head -= 1;
                        }
                        BODY => {
                            in_body -= 1;
                        }
                        _ => (),
                    },
                    HtmlToken::Text { text } if in_head == 0 => {
                        if let Some((href_url, href_host)) = last_href
                            .as_ref()
                            .and_then(|href| {
                                Some((href.url_parsed.as_deref()?, href.host.as_deref()?))
                            })
                            .filter(|_| can_contain_url(text))
                        {
                            for token in TypesTokenizer::new(text.as_ref())
                                .tokenize_numbers(false)
                                .tokenize_urls(true)
                                .tokenize_urls_without_scheme(true)
                                .tokenize_emails(true)
                            {
                                let text_url = match token.word {
                                    TokenType::Url(url) => to_lowercase_cow(url),
                                    TokenType::UrlNoScheme(url) => {
                                        let url = to_lowercase_cow(url);
                                        let mut with_scheme = String::with_capacity(url.len() + 7);
                                        with_scheme.push_str("http://");
                                        with_scheme.push_str(url.as_ref());
                                        Cow::Owned(with_scheme)
                                    }
                                    _ => continue,
                                };
                                let text_url_parsed =
                                    if let Ok(text_url_parsed) = text_url.parse::<Uri>() {
                                        text_url_parsed
                                    } else {
                                        continue;
                                    };

                                if href_url.scheme().map(|s| s.as_str()).unwrap_or_default()
                                    == "http"
                                    && text_url_parsed
                                        .scheme()
                                        .map(|s| s.as_str())
                                        .unwrap_or_default()
                                        == "https"
                                {
                                    // The anchor text contains a distinct scheme compared to the target URL
                                    ctx.result.add_tag("HTTP_TO_HTTPS");
                                }

                                if let Some(text_url_host) = text_url_parsed.host() {
                                    let text_url_host = Hostname::new(text_url_host);

                                    if text_url_host.sld_or_default() != href_host.sld_or_default()
                                    {
                                        // The anchor text contains a different domain than the target URL
                                        ctx.result.add_tag("PHISHING");
                                    }
                                }
                            }
                        }
                    }
                    _ => (),
                }
            }

            if is_body_part {
                let is_whole = !ctx.input.texts.is_cut(part_id as u32);
                if is_whole && (in_head != 0 || in_body != 0) {
                    // HTML tags are not properly closed
                    ctx.result.add_tag("HTML_UNBALANCED_TAG");
                }

                let mut html_words = 0;
                let mut html_uris = 0;
                let mut html_text_chars = 0;

                for token in tokens {
                    match token {
                        TokenType::Alphabetic(s) | TokenType::Alphanumeric(s) => {
                            html_words += 1;
                            html_text_chars += s.len();
                        }
                        TokenType::Email(s) => {
                            html_words += 1;
                            html_text_chars += s.address.len();
                        }
                        TokenType::Url(_) | TokenType::UrlNoScheme(_) => {
                            html_uris += 1;
                        }
                        _ => (),
                    }
                }

                match html_text_chars {
                    _ if !is_whole => (),
                    0..1024 => {
                        ctx.result.add_tag("HTML_SHORT_1");
                    }
                    1024..1536 => {
                        ctx.result.add_tag("HTML_SHORT_2");
                    }
                    1536..2048 => {
                        ctx.result.add_tag("HTML_SHORT_3");
                    }
                    _ => (),
                }

                if (!has_link_to_img || html_text_chars >= 2048)
                    && (html_img_words as f64 / (html_words as f64 + html_img_words as f64) > 0.5)
                {
                    // Message contains more images than text
                    ctx.result.add_tag("HTML_TEXT_IMG_RATIO");
                }

                if is_whole && html_uris > 0 && html_words == 0 {
                    // Message only contains URIs in HTML
                    ctx.result.add_tag("BODY_URI_ONLY");
                }
            }
        }
    }
}

fn can_contain_url(text: &str) -> bool {
    text.as_bytes()
        .iter()
        .any(|byte| matches!(byte, b'.' | b'['))
}

#[cfg(test)]
mod image_size_tests {
    use super::*;
    use crate::{MessageTexts, SpamFilterInput};
    use mail_parser::MessageParser;
    use std::collections::BTreeSet;

    fn analyze(html: &str) -> BTreeSet<String> {
        let raw = format!(
            "From: sender@example.org\r\nTo: recipient@example.net\r\nSubject: Image sizing\r\n\
             MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}"
        );
        let message = MessageParser::new().parse(raw.as_bytes()).unwrap();
        let texts = MessageTexts::new(&message, Default::default());
        let mut ctx = SpamFilterContext::new(SpamFilterInput::from_message(&message, &texts, 0));
        SpamFilterContext::analyze_html(&mut ctx);
        ctx.result.tags.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn small_inline_icon_and_auto_logo_are_not_large() {
        for image in [
            r#"<img src="https://images.example.org/icon.png" style="display:block;width:12px;height:12px">"#,
            r#"<img src="https://images.example.org/logo.png" width="103" style="width:103px;height:auto;max-width:100%">"#,
        ] {
            let tags = analyze(&format!(
                "<body><p>A useful notification with a short ordinary text description.</p>\
                 <a href=\"https://example.org/\">{image}</a></body>"
            ));
            assert!(tags.contains("HAS_LINK_TO_IMG"));
            assert!(tags.contains("HAS_EXTERNAL_IMG"));
            assert!(tags.contains("HTML_SHORT_1"));
            assert!(!tags.contains("HAS_LINK_TO_LARGE_IMG"));
            assert!(!tags.contains("HTML_TEXT_IMG_RATIO"));
        }
    }

    #[test]
    fn every_linked_image_is_checked_without_erasing_previous_large_images() {
        for images in [
            r#"<img src="same.png" width="12" height="12"><img src="same.png" width="300" height="200">"#,
            r#"<img src="same.png" width="300" height="200"><img src="same.png" width="12" height="12">"#,
        ] {
            let tags = analyze(&format!(
                "<body><a href=\"https://example.org/\">{images}</a></body>"
            ));
            assert!(tags.contains("HAS_LINK_TO_LARGE_IMG"));
        }
        let tags = analyze(
            r#"<body><a href="https://example.org/"><img width="12" height="12"></a>
               <img width="800" height="600"></body>"#,
        );
        assert!(!tags.contains("HAS_LINK_TO_LARGE_IMG"));
        assert!(tags.contains("HTML_TEXT_IMG_RATIO"));
    }

    #[test]
    fn first_duplicate_html_attribute_wins() {
        for image in [
            r#"<img width="300" width="12" height="12">"#,
            r#"<img style="width:300px;height:12px" style="width:12px;height:12px">"#,
        ] {
            let tags = analyze(&format!(
                "<body><a href=\"https://example.org/\">{image}</a></body>"
            ));
            assert!(tags.contains("HAS_LINK_TO_LARGE_IMG"));
        }
    }

    #[test]
    fn unknown_image_presence_preserves_image_only_risk_without_inventing_size() {
        let tags =
            analyze(r#"<body><a href="https://example.org/"><img src="image.png"></a></body>"#);
        assert!(tags.contains("HAS_LINK_TO_IMG"));
        assert!(tags.contains("HTML_TEXT_IMG_RATIO"));
        assert!(!tags.contains("HAS_LINK_TO_LARGE_IMG"));
    }

    #[test]
    fn independent_html_risks_are_unchanged() {
        let tags = analyze(
            r#"<body><meta http-equiv="refresh" content="0;url=https://other.example/">
               <a href="https://other.example/">https://example.org/
               <img src="data:text/html;base64,PHNjcmlwdD4=" style="width:12px;height:12px"></a>"#,
        );
        for tag in [
            "PHISHING",
            "HTML_META_REFRESH_URL",
            "HAS_DATA_URI",
            "HTML_UNBALANCED_TAG",
        ] {
            assert!(tags.contains(tag), "{tag}: {tags:?}");
        }
    }
}
