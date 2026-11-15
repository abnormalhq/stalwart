/*
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Size evidence from image presentation attributes and inline CSS, not a browser layout.
//! Missing or layout-dependent dimensions never become invented pixel dimensions.

use std::borrow::Cow;

const MAX_PIXELS: f64 = 1_000_000_000.0;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Length {
    Pixels(f64),
    // A bare percentage: layout-dependent, otherwise treated as Unknown.
    Percent,
    Unknown,
    NoMaximum,
}

#[derive(Clone, Copy, Debug)]
struct Bounds {
    lower: f64,
    upper: Option<f64>,
}

impl Bounds {
    fn new(size: Length, minimum: Length, maximum: Length) -> Self {
        let (mut lower, mut upper) = match size {
            Length::Pixels(value) => (value, Some(value)),
            _ => (0.0, None),
        };
        // CSS applies the maximum before the minimum: min-width wins a conflict.
        // A layout-dependent maximum (such as max-width:100%) cannot be resolved, so
        // it keeps the declared size as evidence instead of hiding a large image.
        match maximum {
            Length::Pixels(value) => {
                lower = lower.min(value);
                upper = Some(upper.map_or(value, |upper| upper.min(value)));
            }
            Length::Percent | Length::Unknown | Length::NoMaximum => (),
        }
        match minimum {
            Length::Pixels(value) => {
                lower = lower.max(value);
                upper = upper.map(|upper| upper.max(value));
            }
            Length::Percent | Length::Unknown => upper = None,
            Length::NoMaximum => (),
        }
        Self { lower, upper }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ImageSize {
    width: Bounds,
    height: Bounds,
}

impl ImageSize {
    pub(crate) fn new(width: Option<&str>, height: Option<&str>, style: Option<&str>) -> Self {
        let mut values = [
            html_length(width),
            html_length(height),
            Length::Pixels(0.0),
            Length::Pixels(0.0),
            Length::NoMaximum,
            Length::NoMaximum,
        ];
        if let Some(style) = style {
            let mut declarations: [Option<(Length, bool)>; 6] = [None; 6];
            let style = without_comments(style);
            for declaration in split_declarations(&style) {
                let Some((property, value)) = declaration.split_once(':') else {
                    continue;
                };
                let Some(property) = identifier(property.trim()) else {
                    continue;
                };
                let (value, important) = priority(value);
                for (index, name) in [
                    "width",
                    "height",
                    "min-width",
                    "min-height",
                    "max-width",
                    "max-height",
                ]
                .iter()
                .enumerate()
                {
                    if property != *name && property != "all" {
                        continue;
                    }
                    if property == "all" && !is_global_keyword(value) {
                        continue;
                    }
                    let Some(value) = css_length(value, index) else {
                        continue;
                    };
                    if declarations[index].is_none_or(|(_, previous)| important || !previous) {
                        declarations[index] = Some((value, important));
                    }
                }
            }
            for (index, (value, declaration)) in values.iter_mut().zip(declarations).enumerate() {
                if let Some((replacement, _)) = declaration {
                    // width:100% cannot be resolved without layout; a pixel HTML
                    // attribute remains the best evidence of the intended size.
                    if index < 2
                        && replacement == Length::Percent
                        && matches!(value, Length::Pixels(_))
                    {
                        continue;
                    }
                    *value = replacement;
                }
            }
        }
        Self {
            width: Bounds::new(values[0], values[2], values[4]),
            height: Bounds::new(values[1], values[3], values[5]),
        }
    }

    fn is_zero(&self) -> bool {
        self.width.upper == Some(0.0) || self.height.upper == Some(0.0)
    }

    pub(crate) fn is_large(&self) -> bool {
        !self.is_zero() && self.width.lower + self.height.lower >= 210.0
    }

    pub(crate) fn word_weight(&self) -> u64 {
        if self.is_zero() {
            return 0;
        }
        let dimensions = self.width.lower + self.height.lower;
        if dimensions > 100.0 {
            return (dimensions / 100.0) as u64;
        }
        // An unknown-size image still exists. A single presence word preserves the
        // image-only heuristic, without asserting that its geometry is large.
        let upper = self.width.upper.zip(self.height.upper).map(|(w, h)| w + h);
        u64::from(upper.is_none_or(|upper| upper > 100.0))
    }
}

// HTML dimension values: leading digits with an optional fraction; trailing text such
// as "px" is ignored, and a percentage is layout-dependent.
fn html_length(value: Option<&str>) -> Length {
    let Some(value) = value.map(|value| value.trim_start_matches([' ', '\t', '\n', '\r', '\x0c']))
    else {
        return Length::Unknown;
    };
    let bytes = value.as_bytes();
    let mut end = bytes
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if end == 0 {
        return Length::Unknown;
    }
    let integer = end;
    if bytes.get(end) == Some(&b'.') {
        let fraction = bytes[end + 1..]
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        end += 1 + fraction;
    }
    if bytes.get(end) == Some(&b'%') {
        return Length::Unknown;
    }
    let number = if end == integer + 1 {
        &value[..integer]
    } else {
        &value[..end]
    };
    number
        .parse::<f64>()
        .map(|value| Length::Pixels(value.min(MAX_PIXELS)))
        .unwrap_or(Length::Unknown)
}

fn is_global_keyword(value: &str) -> bool {
    identifier(value).is_some_and(|value| {
        matches!(
            value.as_str(),
            "initial" | "inherit" | "unset" | "revert" | "revert-layer"
        )
    })
}

fn css_length(value: &str, index: usize) -> Option<Length> {
    if let Some(keyword) = identifier(value) {
        return match keyword.as_str() {
            "initial" | "unset" => Some(match index {
                0 | 1 => Length::Unknown,
                2 | 3 => Length::Pixels(0.0),
                _ => Length::NoMaximum,
            }),
            "inherit" | "revert" | "revert-layer" | "min-content" | "max-content"
            | "fit-content" | "stretch" | "contain" => Some(Length::Unknown),
            "auto" if index < 4 => Some(Length::Unknown),
            "none" if index >= 4 => Some(Length::NoMaximum),
            _ => None,
        };
    }
    if let Some(open) = value.find('(') {
        let function = identifier(&value[..open])?;
        if !value.ends_with(')') || !balanced_function(&value[open..]) {
            return None;
        }
        if function == "fit-content" {
            let argument = value[open + 1..value.len() - 1].trim();
            if number_end(argument).is_some() {
                return css_length(argument, index).map(|_| Length::Unknown);
            }
            let mut parser = MathParser {
                text: argument,
                pos: 0,
                depth: 1,
            };
            return (matches!(parser.atom()?, MathType::Power(1) | MathType::Unknown)
                && parser.next_nonspace() == argument.len())
            .then_some(Length::Unknown);
        }
        return matches!(
            math_function(&function, &value[open + 1..value.len() - 1], 0),
            Some(MathType::Power(1) | MathType::Unknown)
        )
        .then_some(Length::Unknown);
    }
    let end = number_end(value)?;
    let number = value[..end].parse::<f64>().ok()?;
    if number < 0.0 || number.is_nan() {
        return None;
    }
    let unit = &value[end..];
    if unit == "%" {
        return Some(Length::Percent);
    }
    if unit.is_empty() {
        return (number == 0.0).then_some(Length::Pixels(0.0));
    }
    let unit = identifier(unit)?;
    let factor = match unit.as_str() {
        "px" => 1.0,
        "in" => 96.0,
        "cm" => 96.0 / 2.54,
        "mm" => 96.0 / 25.4,
        "q" => 96.0 / 101.6,
        "pt" => 96.0 / 72.0,
        "pc" => 16.0,
        "em" | "ex" | "cap" | "ch" | "ic" | "rem" | "lh" | "rlh" | "vw" | "vh" | "vi" | "vb"
        | "vmin" | "vmax" | "svw" | "svh" | "svi" | "svb" | "svmin" | "svmax" | "lvw" | "lvh"
        | "lvi" | "lvb" | "lvmin" | "lvmax" | "dvw" | "dvh" | "dvi" | "dvb" | "dvmin" | "dvmax"
        | "cqw" | "cqh" | "cqi" | "cqb" | "cqmin" | "cqmax" => {
            return Some(Length::Unknown);
        }
        _ => return None,
    };
    Some(Length::Pixels((number * factor).min(MAX_PIXELS)))
}

fn number_end(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    let mut pos = usize::from(matches!(bytes.first(), Some(b'+' | b'-')));
    let start = pos;
    while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
        pos += 1;
    }
    let mut digits = pos - start;
    if bytes.get(pos) == Some(&b'.') && bytes.get(pos + 1).is_some_and(u8::is_ascii_digit) {
        pos += 1;
        let start = pos;
        while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
            pos += 1;
        }
        digits += pos - start;
    }
    if digits == 0 {
        return None;
    }
    if matches!(bytes.get(pos), Some(b'e' | b'E')) {
        let exponent = pos;
        pos += 1;
        if matches!(bytes.get(pos), Some(b'+' | b'-')) {
            pos += 1;
        }
        let start = pos;
        while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
            pos += 1;
        }
        if pos == start {
            pos = exponent;
        }
    }
    Some(pos)
}

// Validate the supported math/variable grammar without evaluating layout. This
// prevents invalid declarations such as calc(1px +) from replacing earlier sizes.
#[derive(Clone, Copy)]
enum MathType {
    Power(i8), // Length exponent; zero is a unitless number.
    Unknown,
}

impl MathType {
    fn sum(self, other: Self) -> Option<Self> {
        match (self, other) {
            (Self::Power(a), Self::Power(b)) if a == b => Some(self),
            (Self::Unknown, _) | (_, Self::Unknown) => Some(Self::Unknown),
            _ => None,
        }
    }

    fn product(self, other: Self, divide: bool) -> Option<Self> {
        match (self, other) {
            (Self::Power(a), Self::Power(b)) => {
                let result = if divide {
                    a.checked_sub(b)
                } else {
                    a.checked_add(b)
                }?;
                (result.abs() <= 32).then_some(Self::Power(result))
            }
            _ => Some(Self::Unknown),
        }
    }
}

struct MathParser<'a> {
    text: &'a str,
    pos: usize,
    depth: usize,
}

impl<'a> MathParser<'a> {
    fn parse(text: &'a str, depth: usize) -> Option<MathType> {
        if depth > 32 {
            return None;
        }
        let mut parser = Self {
            text,
            pos: 0,
            depth,
        };
        let result = parser.sum()?;
        (parser.next_nonspace() == text.len()).then_some(result)
    }

    fn next_nonspace(&self) -> usize {
        self.pos + self.text[self.pos..].len() - self.text[self.pos..].trim_start().len()
    }

    fn sum(&mut self) -> Option<MathType> {
        let mut result = self.product()?;
        loop {
            let next = self.next_nonspace();
            if !matches!(self.text.as_bytes().get(next), Some(b'+' | b'-')) {
                return Some(result);
            }
            // CSS binary + and - require surrounding whitespace.
            if next == self.pos || !self.text.as_bytes().get(next + 1)?.is_ascii_whitespace() {
                return None;
            }
            self.pos = next + 1;
            result = result.sum(self.product()?)?;
        }
    }

    fn product(&mut self) -> Option<MathType> {
        let mut result = self.atom()?;
        loop {
            let next = self.next_nonspace();
            let operator = self.text.as_bytes().get(next);
            if !matches!(operator, Some(b'*' | b'/')) {
                return Some(result);
            }
            self.pos = next + 1;
            result = result.product(self.atom()?, operator == Some(&b'/'))?;
        }
    }

    fn atom(&mut self) -> Option<MathType> {
        self.pos = self.next_nonspace();
        let start = self.pos;
        let remaining = &self.text[start..];
        if let Some(end) = number_end(remaining) {
            self.pos += end;
            let unit_start = self.pos;
            while let Some(&ch) = self.text.as_bytes().get(self.pos) {
                if ch.is_ascii_whitespace() || matches!(ch, b'+' | b'-' | b'*' | b'/' | b')' | b',')
                {
                    break;
                }
                self.pos += 1;
            }
            if self.pos == unit_start {
                return Some(MathType::Power(0));
            }
            let token = self.text[start..self.pos].trim_start_matches(['+', '-']);
            return css_length(token, 0).map(|_| MathType::Power(1));
        }
        let open = remaining.find('(')?;
        let name = &remaining[..open];
        if !name.is_empty() && identifier(name).is_none() {
            return None;
        }
        let end = function_end(&remaining[open..])?;
        self.pos = start + open + end;
        let content = &remaining[open + 1..open + end - 1];
        if name.is_empty() {
            Self::parse(content, self.depth + 1)
        } else {
            math_function(&identifier(name)?, content, self.depth + 1)
        }
    }
}

fn math_function(name: &str, content: &str, depth: usize) -> Option<MathType> {
    if depth > 32 || content.trim().is_empty() {
        return None;
    }
    let args = function_args(content)?;
    if name == "var" {
        // A fallback may be empty or may not be a length until substitution.
        let variable = args[0];
        return (variable.starts_with("--") && variable.len() > 2 && css_ident(variable))
            .then_some(MathType::Unknown);
    }
    if name == "env" {
        let mut parts = args[0].split_ascii_whitespace();
        let variable = parts.next()?;
        return (css_ident(variable)
            && !variable.starts_with("--")
            && parts.all(|part| !part.is_empty() && part.bytes().all(|ch| ch.is_ascii_digit())))
        .then_some(MathType::Unknown);
    }
    if args.iter().any(|arg| arg.is_empty()) {
        return None;
    }
    match name {
        "calc" if args.len() == 1 => MathParser::parse(args[0], depth + 1),
        "min" | "max" | "clamp" if name != "clamp" || args.len() == 3 => {
            let mut result = MathParser::parse(args[0], depth + 1)?;
            for arg in &args[1..] {
                result = result.sum(MathParser::parse(arg, depth + 1)?)?;
            }
            Some(result)
        }
        _ => None,
    }
}

// Split only top-level commas. Escapes, nested blocks and strings in a var()
// fallback are tokens, not function-argument delimiters.
fn function_args(content: &str) -> Option<Vec<&str>> {
    let bytes = content.as_bytes();
    let mut args = Vec::new();
    let mut stack = Vec::new();
    let mut quote = None;
    let mut start = 0;
    let mut pos = 0;
    while pos < bytes.len() {
        let ch = bytes[pos];
        if ch == b'\\' {
            pos = escaped_end(bytes, pos);
            continue;
        }
        if let Some(current) = quote {
            if ch == current {
                quote = None;
            } else if matches!(ch, b'\n' | b'\r' | 0x0c) {
                return None;
            }
        } else {
            match ch {
                b'\'' | b'"' => quote = Some(ch),
                b'(' | b'[' | b'{' => stack.push(ch),
                b')' | b']' | b'}' => {
                    let expected = match ch {
                        b')' => b'(',
                        b']' => b'[',
                        _ => b'{',
                    };
                    if stack.pop() != Some(expected) {
                        return None;
                    }
                }
                b',' if stack.is_empty() => {
                    args.push(content[start..pos].trim());
                    start = pos + 1;
                }
                b';' | b'!' if stack.is_empty() => return None,
                _ => (),
            }
        }
        pos += 1;
    }
    if !stack.is_empty() || quote.is_some() {
        return None;
    }
    args.push(content[start..].trim());
    Some(args)
}

fn css_ident(value: &str) -> bool {
    let mut chars = value.chars().peekable();
    let mut tokens = Vec::new();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let Some(next) = chars.next() else {
                return false;
            };
            if matches!(next, '\n' | '\r' | '\u{000c}') {
                return false;
            }
            if next.is_ascii_hexdigit() {
                for _ in 1..6 {
                    if chars.peek().is_some_and(char::is_ascii_hexdigit) {
                        chars.next();
                    } else {
                        break;
                    }
                }
                if chars.peek().is_some_and(char::is_ascii_whitespace) {
                    if chars.next() == Some('\r') && chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                }
            }
            tokens.push((next, true));
        } else {
            if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' && (ch as u32) < 128 {
                return false;
            }
            tokens.push((ch, false));
        }
    }
    let start = |(ch, escaped): &(char, bool)| {
        *escaped || *ch == '_' || ch.is_ascii_alphabetic() || (*ch as u32) >= 128
    };
    tokens.first().is_some_and(|token| {
        start(token)
            || token.0 == '-'
                && tokens
                    .get(1)
                    .is_some_and(|next| start(next) || next.0 == '-')
    })
}

// Decode identifier escapes, but do not join tokens separated by whitespace or comments.
fn identifier(value: &str) -> Option<String> {
    let mut result = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        let ch = if ch == '\\' {
            let next = chars.next()?;
            if next.is_ascii_hexdigit() {
                let mut code = next.to_digit(16)?;
                for _ in 1..6 {
                    let Some(next) = chars.peek().and_then(|ch| ch.to_digit(16)) else {
                        break;
                    };
                    code = code * 16 + next;
                    chars.next();
                }
                if chars.peek().is_some_and(|ch| ch.is_ascii_whitespace()) {
                    let whitespace = chars.next();
                    if whitespace == Some('\r') && chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                }
                char::from_u32(code)?
            } else {
                next
            }
        } else {
            ch
        };
        if !ch.is_ascii_alphabetic() && ch != '-' {
            return None;
        }
        result.push(ch.to_ascii_lowercase());
    }
    (!result.is_empty()).then_some(result)
}

fn without_comments(value: &str) -> Cow<'_, str> {
    if !value.contains("/*") {
        return Cow::Borrowed(value);
    }
    let bytes = value.as_bytes();
    let mut output = String::with_capacity(value.len());
    let mut quote = None;
    let mut pos = 0;
    let mut copied = 0;
    while pos < bytes.len() {
        match bytes[pos] {
            b'\\' => pos = escaped_end(bytes, pos),
            b'\n' | b'\r' | 0x0c if quote.is_some() => {
                quote = None;
                pos += 1;
            }
            b'\'' | b'"' if quote == Some(bytes[pos]) => {
                quote = None;
                pos += 1;
            }
            b'\'' | b'"' if quote.is_none() => {
                quote = Some(bytes[pos]);
                pos += 1;
            }
            b'/' if quote.is_none() && bytes.get(pos + 1) == Some(&b'*') => {
                output.push_str(&value[copied..pos]);
                output.push(' ');
                pos = value[pos + 2..]
                    .find("*/")
                    .map_or(bytes.len(), |end| pos + end + 4);
                copied = pos;
            }
            _ => pos += 1,
        }
    }
    output.push_str(&value[copied..]);
    Cow::Owned(output)
}

// Only top-level separators delimit declarations. Quotes, escapes and nested blocks
// must not turn a URL or custom-property value into a size declaration.
fn split_declarations(style: &str) -> Vec<&str> {
    let bytes = style.as_bytes();
    let mut output = Vec::new();
    let mut stack = Vec::new();
    let mut quote = None;
    let mut start = 0;
    let mut pos = 0;
    let mut valid = true;
    while pos < bytes.len() {
        let ch = bytes[pos];
        if ch == b'\\' {
            pos = escaped_end(bytes, pos);
            continue;
        }
        if let Some(current) = quote {
            if ch == current {
                quote = None;
            } else if matches!(ch, b'\n' | b'\r' | 0x0c) {
                // CSS bad-string recovery ends the string at an unescaped newline.
                quote = None;
                valid = false;
            }
        } else {
            match ch {
                b'\'' | b'"' => quote = Some(ch),
                b'(' | b'[' | b'{' => stack.push(ch),
                b')' | b']' | b'}' => {
                    let expected = match ch {
                        b')' => b'(',
                        b']' => b'[',
                        _ => b'{',
                    };
                    if stack.pop() != Some(expected) {
                        valid = false;
                    }
                }
                b';' if stack.is_empty() => {
                    if valid {
                        output.push(&style[start..pos]);
                    }
                    start = pos + 1;
                    valid = true;
                }
                _ => (),
            }
        }
        pos += 1;
    }
    if valid && quote.is_none() && stack.is_empty() {
        output.push(&style[start..]);
    }
    output
}

fn escaped_end(bytes: &[u8], pos: usize) -> usize {
    (pos + if bytes.get(pos + 1) == Some(&b'\r') && bytes.get(pos + 2) == Some(&b'\n') {
        3
    } else {
        2
    })
    .min(bytes.len())
}

fn priority(value: &str) -> (&str, bool) {
    let value = value.trim();
    // A bang inside a function/string cannot be a trailing priority token.
    if let Some(bang) = value.rfind('!') {
        if identifier(value[bang + 1..].trim()).as_deref() == Some("important") {
            let prefix = value[..bang].trim_end();
            return (prefix, true);
        }
    }
    (value, false)
}

fn balanced_function(value: &str) -> bool {
    function_end(value) == Some(value.len())
}

fn function_end(value: &str) -> Option<usize> {
    if !value.starts_with('(') {
        return None;
    }
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(current) = quote {
            if ch == current {
                quote = None;
            } else if matches!(ch, '\n' | '\r' | '\u{000c}') {
                return None;
            }
        } else {
            match ch {
                '\'' | '"' => quote = Some(ch),
                '(' => depth += 1,
                ')' => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(index + 1);
                    }
                }
                _ => (),
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn size(width: Option<&str>, height: Option<&str>, style: &str) -> ImageSize {
        ImageSize::new(width, height, Some(style))
    }

    #[test]
    fn no_invented_dimensions() {
        for image in [
            size(None, None, ""),
            size(Some("103"), None, "height:auto"),
            size(Some("103"), Some("600"), "height:auto"),
            size(None, None, "width:100%;height:auto"),
        ] {
            assert!(!image.is_large(), "{image:?}");
            assert_eq!(image.word_weight(), 1);
        }
        assert!(size(Some("210"), None, "").is_large());
        assert!(!size(Some("209"), None, "").is_large());
        assert!(size(Some("105"), Some("105"), "").is_large());
        assert!(!size(Some("104"), Some("105"), "").is_large());
    }

    #[test]
    fn percentage_css_size_keeps_html_attribute() {
        assert!(size(
            Some("600"),
            Some("400"),
            "width:100%;max-width:600px;height:auto"
        )
        .is_large());
        assert!(size(Some("300"), None, "width:50%").is_large());
        assert!(!size(Some("300"), None, "width:50%;max-width:100px").is_large());
        assert!(!size(None, Some("12"), "width:50%").is_large());
        assert!(!size(Some("300"), None, "width:calc(100% - 1px)").is_large());
    }

    #[test]
    fn html_dimension_values() {
        assert!(size(Some("600px"), Some("400px"), "").is_large());
        assert!(size(Some(" 300.5"), None, "").is_large());
        assert!(size(Some("210."), None, "").is_large());
        assert!(!size(Some("50%"), None, "").is_large());
        assert!(!size(Some("px600"), None, "").is_large());
        assert_eq!(size(Some("12px"), Some("12px"), "").word_weight(), 0);
    }

    #[test]
    fn inline_precedence_and_invalid_declarations() {
        assert!(size(Some("12"), Some("12"), "width:500px;height:300px").is_large());
        assert!(!size(Some("800"), Some("600"), "width:12px;height:12px").is_large());
        for style in [
            "width:300px;width:-1px",
            "width:300px;width:NaN",
            "width:300px;width:12 px",
            "width:300px;width:5.px",
            "width:300px;width:bogus",
            "width:300px;width:20",
            "width:300px;width:url('x')",
        ] {
            assert!(size(None, Some("12"), style).is_large(), "{style}");
        }
        for style in [
            "width:300px;width:auto",
            "width:300px;width:10%",
            "width:300px;width:2em",
            "width:300px;width:calc(100% - 2px)",
            "width:300px;width:var(--size)",
            "width:300px;width:var(--size, 'unknown') !important",
        ] {
            assert!(!size(None, Some("12"), style).is_large(), "{style}");
        }
    }

    #[test]
    fn function_syntax_does_not_hide_known_large_images() {
        for value in [
            "calc(1px +)",
            "calc(1px + red)",
            "calc(1px+2px)",
            "calc(1px + 1)",
            "calc(1px * 1px)",
            "calc(1)",
            "calc()",
            "calc (1px)",
            "min(,)",
            "min(1px,)",
            "min(1px, 2)",
            "clamp(1px, 2px)",
            "clamp(1px, 2px, 3px, 4px)",
            "var(red)",
            "var(foo)",
            "var(--)",
            "var(--x --y)",
            "env(1name)",
            "env(--x)",
            "env(name -1)",
            "var(--x, 1px!important)",
            "fit-content(auto)",
            "fit-content(-1px)",
            "fit-content(1px + 2px)",
            "fit-content(fit-content(1px))",
        ] {
            let style = format!("width:300px;width:{value}");
            assert!(size(None, Some("12"), &style).is_large(), "{value}");
        }
        for value in [
            "calc(100% - 1px)",
            "calc((1px + 2px) * 3)",
            "calc(3 * (1px + 2px))",
            "calc(3px / 2)",
            "min(1px, 20%)",
            "max(1em, 2px)",
            "clamp(1px, 2%, 3px)",
            "var(--size)",
            "var(--s2_界)",
            "var(--size,)",
            "var(--size, 'unknown')",
            "var(--size, var(--other, 2px))",
            "env(safe-area-inset-left)",
            "env(viewport-segment-width 0 0, 1px)",
            "fit-content(10%)",
            "fit-content(calc(100% - 2px))",
        ] {
            let style = format!("width:300px;width:{value}");
            assert!(!size(None, Some("12"), &style).is_large(), "{value}");
        }
        let nested = format!("{}1px{}", "calc(".repeat(128), ")".repeat(128));
        assert!(size(None, None, &format!("width:300px;width:{nested}")).is_large());
    }

    #[test]
    fn priorities_comments_and_escapes() {
        for style in [
            "width:300px!important;width:12px",
            "width:12px!important;width:300px!important",
            "width:300px ! /* comment */ IMPORTANT; width:12px",
            "w\\69 dth:300p\\78",
        ] {
            assert!(size(None, Some("12"), style).is_large(), "{style}");
        }
        for style in [
            "width:300px;width:12px",
            "width:300px!important;width:auto!important",
            "width:300px;all:initial",
            "width:12px;w/**/idth:300px",
        ] {
            assert!(!size(None, Some("12"), style).is_large(), "{style}");
        }
    }

    #[test]
    fn nested_or_quoted_text_is_not_a_declaration() {
        for style in [
            "width:300px;background:url(';width:12px;')",
            "width:300px;--x:{;width:12px;}",
            "width:300px;--x:[;width:12px;]",
            "width:300px;--x:\";width:12px;\"",
            "width:300px;/* width:12px; */",
            "width:300px;background:url(x;width:12px)",
            "width:300px;background:url(\"/*;width:12px;*/\")",
            "width:300px;--x:\\;width:12px",
            "width:300px;/* unfinished width:12px",
        ] {
            assert!(size(None, Some("12"), style).is_large(), "{style}");
        }
        assert!(!size(None, Some("12"), "width:300px;color:\"bad\n;width:12px").is_large());
        assert!(size(None, Some("12"), "width:300px;--x:\"a\\\r\n;width:12px\"").is_large());
    }

    #[test]
    fn min_max_bounds_and_zero() {
        for style in [
            "width:12px;min-width:300px",
            "width:auto;min-width:300px",
            "width:12px;min-width:300px;max-width:20px",
            "width:300px;max-width:none",
            "width:1000px;max-width:100%",
            "width:1000px;max-width:calc(100% - 1px)",
        ] {
            assert!(size(None, Some("12"), style).is_large(), "{style}");
        }
        for style in ["width:1000px;max-width:12px"] {
            assert!(!size(None, Some("12"), style).is_large(), "{style}");
        }
        assert_eq!(
            size(None, None, "max-width:12px;max-height:12px").word_weight(),
            0
        );
        assert_eq!(size(None, None, "width:12px;height:12px").word_weight(), 0);
        for style in ["width:1000px;height:0", "width:0;height:1000px"] {
            let image = size(None, None, style);
            assert!(!image.is_large());
            assert_eq!(image.word_weight(), 0);
        }
    }

    #[test]
    fn numbers_do_not_overflow_or_round_up_threshold() {
        assert!(size(None, None, "width:1e999px").is_large());
        assert!(size(Some("99999999999999999999999999999999"), None, "").is_large());
        assert!(!size(None, None, "width:104.9px;height:104.9px").is_large());
        assert!(size(None, None, "width:1in;height:2in").is_large());
        assert_eq!(
            size(None, None, "width:1e999px;height:1e999px").word_weight(),
            20_000_000
        );
    }

    #[test]
    fn malformed_styles_are_bounded_and_do_not_panic() {
        let alphabet = [
            'a', 'w', 'i', 'd', 't', 'h', 'p', 'x', '0', '1', '9', '.', '-', '+', ':', ';', '(',
            ')', '[', ']', '{', '}', '\\', '\'', '"', '/', '*', '!', '%', ' ', '\n', '\r', 'é',
            '界',
        ];
        let mut seed = 0x81e2_58a4u64;
        for length in 0..256 {
            let mut style = String::new();
            for _ in 0..length {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                style.push(alphabet[(seed >> 32) as usize % alphabet.len()]);
            }
            for prefix in ["", "width:300px;", "width:12px;height:12px;"] {
                let image = size(None, None, &format!("{prefix}{style}"));
                assert!(image.word_weight() <= 20_000_000);
                assert!(!image.is_large() || image.word_weight() >= 2);
            }
        }
    }
}
