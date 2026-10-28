//! Typed slots. Every value a requester sends must fit one of these exactly,
//! or the request is refused. Nothing is "cleaned up" on the way in: a value
//! either matches its rule or it is rejected.

use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq)]
pub enum InputType {
    Integer { min: i64, max: i64 },
    Text { charset: Charset, max: usize },
    Choice(Vec<String>),
    Date,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    /// ASCII digits only.
    Digits,
    /// ASCII letters and digits only.
    Alnum,
    /// Letters from any alphabet, plus space, hyphen, apostrophe and period.
    Name,
    /// A plain ASCII email address.
    Email,
    /// Digits plus space, plus sign, hyphen, period and parentheses.
    Phone,
    /// ASCII letters, digits, hyphens and underscores. For ids, order numbers and similar codes.
    Code,
    /// One line of visible text in any language. No control or invisible characters.
    Line,
}

impl Charset {
    pub fn parse(word: &str) -> Option<Charset> {
        Some(match word {
            "digits" => Charset::Digits,
            "alnum" => Charset::Alnum,
            "name" => Charset::Name,
            "email" => Charset::Email,
            "phone" => Charset::Phone,
            "code" => Charset::Code,
            "line" => Charset::Line,
            _ => return None,
        })
    }

    pub fn word(self) -> &'static str {
        match self {
            Charset::Digits => "digits",
            Charset::Alnum => "alnum",
            Charset::Name => "name",
            Charset::Email => "email",
            Charset::Phone => "phone",
            Charset::Code => "code",
            Charset::Line => "line",
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Charset::Digits => "ASCII digits only",
            Charset::Alnum => "ASCII letters and digits only",
            Charset::Name => "letters, spaces, hyphens, apostrophes and periods",
            Charset::Email => "a plain ASCII email address",
            Charset::Phone => "digits, spaces and + - . ( )",
            Charset::Code => "ASCII letters, digits, hyphens and underscores",
            Charset::Line => "one line of visible text",
        }
    }
}

/// A value that has passed its rule. Only these ever reach the database.
#[derive(Debug, Clone, PartialEq)]
pub enum Checked {
    Int(i64),
    Text(String),
}

impl Checked {
    pub fn to_sql(&self) -> rusqlite::types::Value {
        match self {
            Checked::Int(i) => rusqlite::types::Value::Integer(*i),
            Checked::Text(s) => rusqlite::types::Value::Text(s.clone()),
        }
    }

    pub fn display(&self) -> String {
        match self {
            Checked::Int(i) => i.to_string(),
            Checked::Text(s) => s.clone(),
        }
    }
}

impl InputType {
    /// Checks a JSON value against this rule. JSON types must match exactly:
    /// a number is never accepted as text and text is never accepted as a number.
    pub fn check_json(&self, v: &Value) -> Option<Checked> {
        match self {
            InputType::Integer { min, max } => {
                if !v.is_i64() && !v.is_u64() {
                    return None;
                }
                let n = v.as_i64()?;
                (n >= *min && n <= *max).then_some(Checked::Int(n))
            }
            _ => self.check_text(v.as_str()?),
        }
    }

    /// Checks a value typed on a command line, where everything arrives as text.
    pub fn check_cli(&self, s: &str) -> Option<Checked> {
        match self {
            InputType::Integer { min, max } => {
                let n = parse_canonical_int(s)?;
                (n >= *min && n <= *max).then_some(Checked::Int(n))
            }
            _ => self.check_text(s),
        }
    }

    fn check_text(&self, s: &str) -> Option<Checked> {
        let ok = match self {
            InputType::Integer { .. } => false,
            InputType::Text { charset, max } => {
                let len = s.chars().count();
                len >= 1 && len <= *max && charset_ok(*charset, s)
            }
            InputType::Choice(options) => options.iter().any(|o| o == s),
            InputType::Date => valid_date(s),
        };
        ok.then(|| Checked::Text(s.to_owned()))
    }

    /// The JSON Schema shown to an AI client so it knows what fits.
    pub fn schema(&self) -> Value {
        match self {
            InputType::Integer { min, max } => json!({"type": "integer", "minimum": min, "maximum": max}),
            InputType::Text { charset, max } => json!({
                "type": "string", "minLength": 1, "maxLength": max,
                "description": format!("Allowed: {}.", charset.describe()),
            }),
            InputType::Choice(options) => json!({"type": "string", "enum": options}),
            InputType::Date => json!({
                "type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
                "description": "A date written YYYY-MM-DD.",
            }),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            InputType::Integer { min, max } => format!("integer {min}..{max}"),
            InputType::Text { charset, max } => format!("text {} max {max}", charset.word()),
            InputType::Choice(options) => format!("choice {}", options.join(", ")),
            InputType::Date => "date".to_owned(),
        }
    }
}

/// Integers must be written one way only: no plus sign, no leading zeros, no spaces.
fn parse_canonical_int(s: &str) -> Option<i64> {
    let digits = s.strip_prefix('-').unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return None;
    }
    if s == "-0" {
        return None;
    }
    s.parse().ok()
}

const APOSTROPHE: char = '\u{27}';

fn charset_ok(cs: Charset, s: &str) -> bool {
    if s.chars().any(|c| c.is_control() || is_invisible(c)) {
        return false;
    }
    match cs {
        Charset::Digits => s.bytes().all(|b| b.is_ascii_digit()),
        Charset::Alnum => s.bytes().all(|b| b.is_ascii_alphanumeric()),
        Charset::Name => {
            !s.starts_with(' ')
                && !s.ends_with(' ')
                && !s.contains("  ")
                && s.chars().any(char::is_alphabetic)
                && s.chars().all(|c| c.is_alphabetic() || c == ' ' || c == '-' || c == '.' || c == APOSTROPHE)
        }
        Charset::Email => valid_email(s),
        Charset::Phone => {
            s.bytes().any(|b| b.is_ascii_digit())
                && s.bytes().all(|b| b.is_ascii_digit() || b" +-.()".contains(&b))
        }
        Charset::Code => s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        Charset::Line => s.trim() == s,
    }
}

fn valid_email(s: &str) -> bool {
    let mut parts = s.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let local_ok = !local.is_empty()
        && local.bytes().all(|b| b.is_ascii_alphanumeric() || b"._%+-".contains(&b))
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..");
    let labels: Vec<&str> = domain.split('.').collect();
    let domain_ok = labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    local_ok && domain_ok
}

fn valid_date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        let part = s.get(r)?;
        if part.bytes().all(|c| c.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    let (Some(y), Some(m), Some(d)) = (num(0..4), num(5..7), num(8..10)) else {
        return false;
    };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    y >= 1 && d >= 1 && d <= days
}

/// Characters that render as nothing, reorder text, or hide data. Several of these
/// ranges, such as the Unicode "tag" block, are used to smuggle hidden instructions
/// to AI models inside text that looks harmless to a person.
pub fn is_invisible(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x034F | 0x061C | 0x115F | 0x1160 | 0x17B4 | 0x17B5 | 0x180B..=0x180F
        | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x206F | 0x3164 | 0xFE00..=0xFE0F
        | 0xFEFF | 0xFFA0 | 0xFFF0..=0xFFFB | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A
        | 0xE000..=0xF8FF | 0xE0000..=0xE0FFF | 0xF0000..=0x10FFFF)
}

/// Rebuilds a stored string for a reply: invisible characters and control characters
/// other than newline and tab are removed, and the result is cut to `max_chars`.
/// Returns the cleaned text and whether anything was changed.
pub fn clean_output(s: &str, max_chars: usize) -> (String, bool) {
    let mut out = String::with_capacity(s.len().min(max_chars * 4));
    let mut changed = false;
    let mut count = 0usize;
    for c in s.chars() {
        if is_invisible(c) || (c.is_control() && c != '\n' && c != '\t') {
            changed = true;
            continue;
        }
        if count == max_chars {
            out.push_str("...[cut]");
            changed = true;
            break;
        }
        out.push(c);
        count += 1;
    }
    (out, changed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mask {
    /// Keep only the last N letters or digits. Punctuation stays so the format is readable.
    Last(usize),
    /// Replace the whole value with a fixed run of stars, hiding even its length.
    All,
}

impl Mask {
    pub fn apply(self, s: &str) -> String {
        match self {
            Mask::All => "********".to_owned(),
            Mask::Last(n) => {
                let total = s.chars().filter(|c| c.is_alphanumeric()).count();
                let hide = total.saturating_sub(n);
                let mut seen = 0usize;
                s.chars()
                    .map(|c| {
                        if c.is_alphanumeric() {
                            seen += 1;
                            if seen <= hide {
                                '*'
                            } else {
                                c
                            }
                        } else {
                            c
                        }
                    })
                    .collect()
            }
        }
    }

    pub fn describe(self) -> String {
        match self {
            Mask::Last(n) => format!("masked, last {n} shown"),
            Mask::All => "masked".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(cs: Charset, max: usize) -> InputType {
        InputType::Text { charset: cs, max }
    }

    #[test]
    fn integers_must_be_whole_numbers_in_range() {
        let t = InputType::Integer { min: 1, max: 100 };
        assert_eq!(t.check_json(&json!(7)), Some(Checked::Int(7)));
        assert_eq!(t.check_json(&json!(7.0)), None);
        assert_eq!(t.check_json(&json!(1.5)), None);
        assert_eq!(t.check_json(&json!("7")), None);
        assert_eq!(t.check_json(&json!(0)), None);
        assert_eq!(t.check_json(&json!(101)), None);
        assert_eq!(t.check_json(&json!(u64::MAX)), None);
        assert_eq!(t.check_cli("7"), Some(Checked::Int(7)));
        assert_eq!(t.check_cli("07"), None);
        assert_eq!(t.check_cli("+7"), None);
        assert_eq!(t.check_cli(" 7"), None);
    }

    #[test]
    fn charsets_hold() {
        assert!(text(Charset::Name, 40).check_cli("O\u{27}Brien-Smith").is_some());
        assert!(text(Charset::Name, 40).check_cli("Jos\u{e9} N\u{fa}\u{f1}ez").is_some());
        assert!(text(Charset::Name, 40).check_cli("Smith\u{27} OR \u{27}1\u{27}=\u{27}1").is_none());
        assert!(text(Charset::Name, 40).check_cli("Robert; DROP TABLE").is_none());
        assert!(text(Charset::Alnum, 40).check_cli("bl\u{430}nk").is_none(), "Cyrillic a must fail ASCII rule");
        assert!(text(Charset::Email, 80).check_cli("a.b+c@example.com").is_some());
        assert!(text(Charset::Email, 80).check_cli("a@b@example.com").is_none());
        assert!(text(Charset::Email, 80).check_cli("a@localhost").is_none());
        assert!(text(Charset::Phone, 20).check_cli("+1 (555) 010-2000").is_some());
        assert!(text(Charset::Phone, 20).check_cli("555-0100; rm").is_none());
        assert!(text(Charset::Line, 5).check_cli("toolong").is_none());
    }

    #[test]
    fn hidden_characters_are_refused_on_the_way_in() {
        let line = text(Charset::Line, 200);
        assert!(line.check_cli("hello").is_some());
        assert!(line.check_cli("hello\u{200B}").is_none(), "zero-width space");
        assert!(line.check_cli("hi\u{E0041}\u{E0042}").is_none(), "Unicode tag smuggling");
        assert!(line.check_cli("abc\u{202E}cba").is_none(), "right-to-left override");
        assert!(line.check_cli("two\nlines").is_none());
        assert!(line.check_cli("nul\0byte").is_none());
    }

    #[test]
    fn dates_are_real_dates() {
        assert!(valid_date("2024-02-29"));
        assert!(!valid_date("2023-02-29"));
        assert!(!valid_date("2024-13-01"));
        assert!(!valid_date("2024-1-01"));
        assert!(!valid_date("+024-01-01"));
    }

    #[test]
    fn choices_match_exactly() {
        let t = InputType::Choice(vec!["open".into(), "closed".into()]);
        assert!(t.check_cli("open").is_some());
        assert!(t.check_cli("Open").is_none());
        assert!(t.check_cli("open ").is_none());
    }

    #[test]
    fn output_cleaning_strips_hidden_text() {
        let (s, changed) = clean_output("ok\u{E0049}\u{E0047}\u{200B} fine\u{7}", 100);
        assert_eq!(s, "ok fine");
        assert!(changed);
        let (s, changed) = clean_output("abcdef", 3);
        assert_eq!(s, "abc...[cut]");
        assert!(changed);
    }

    #[test]
    fn masks() {
        assert_eq!(Mask::Last(4).apply("000-12-3456"), "***-**-3456");
        assert_eq!(Mask::Last(2).apply("555-0100"), "***-**00");
        assert_eq!(Mask::All.apply("anything at all"), "********");
    }
}
