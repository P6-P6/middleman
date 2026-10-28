//! The rules language. This file is the only place where anyone says what is allowed.
//! Anything a rules file does not describe does not exist for a requester.
//!
//! The language is deliberately tiny. It has no loops, no expressions and no way to
//! reach the outside world, so a rules file can never become an attack by itself.
//! It is also strict: an unknown word, a missing piece or a column without a level
//! stops the middleman from starting at all.
//!
//! ```text
//! database shop.db
//! audit    audit.db
//!
//! levels
//!   0 public
//!   1 basic
//!
//! table customers
//!   id    level 0
//!   name  level 1
//!   together zip + birthdate level 2
//!
//! requester support-agent
//!   key-sha256  <64 hex characters>
//!   machines    any
//!   clearance   1
//!   reasons     support
//!   budget      calls 30 per minute
//!
//! action read_customer
//!   about    Read one customer by id.
//!   kind     read
//!   table    customers
//!   input    customer_id: integer 1..999999
//!   where    id = customer_id
//!   returns  name
//!   rows     1
//!   reasons  support
//! ```

use crate::inputs::{is_invisible, Charset, InputType, Mask};
use rusqlite::{Connection, OpenFlags};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const MAX_RULES_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
pub struct Rules {
    pub database: PathBuf,
    pub audit: PathBuf,
    pub levels: BTreeMap<u8, String>,
    pub tables: BTreeMap<String, Table>,
    pub requesters: Vec<Requester>,
    pub actions: Vec<Action>,
}

#[derive(Debug)]
pub struct Table {
    pub name: String,
    pub columns: Vec<(String, u8)>,
    pub together: Vec<Together>,
}

impl Table {
    pub fn level(&self, column: &str) -> Option<u8> {
        self.columns.iter().find(|(c, _)| c == column).map(|(_, l)| *l)
    }
}

#[derive(Debug, Clone)]
pub struct Together {
    pub columns: Vec<String>,
    pub level: u8,
}

#[derive(Debug)]
pub struct Requester {
    pub name: String,
    pub line: usize,
    pub key_sha256: [u8; 32],
    /// `None` means any machine.
    pub machines: Option<Vec<String>>,
    pub clearance: u8,
    pub reasons: Vec<String>,
    pub budgets: Vec<Budget>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Budget {
    pub kind: BudgetKind,
    pub limit: u32,
    pub window_secs: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetKind {
    Calls,
    Rows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Read,
    Insert,
    Update,
}

impl Kind {
    pub fn word(self) -> &'static str {
        match self {
            Kind::Read => "read",
            Kind::Insert => "insert",
            Kind::Update => "update",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Lt,
    Le,
    Gt,
    Ge,
}

impl Op {
    fn parse(s: &str) -> Option<Op> {
        Some(match s {
            "=" => Op::Eq,
            "<" => Op::Lt,
            "<=" => Op::Le,
            ">" => Op::Gt,
            ">=" => Op::Ge,
            _ => return None,
        })
    }

    pub fn sql(self) -> &'static str {
        match self {
            Op::Eq => "=",
            Op::Lt => "<",
            Op::Le => "<=",
            Op::Gt => ">",
            Op::Ge => ">=",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Where {
    pub column: String,
    pub op: Op,
    pub input: String,
}

#[derive(Debug)]
pub struct Action {
    pub name: String,
    pub line: usize,
    pub about: String,
    pub kind: Kind,
    pub table: String,
    pub inputs: Vec<(String, InputType)>,
    pub wheres: Vec<Where>,
    pub returns: Vec<String>,
    pub sets: Vec<(String, String)>,
    pub masks: BTreeMap<String, Mask>,
    /// Column and whether the order is descending.
    pub order: Option<(String, bool)>,
    /// Most rows a read may return, or an update may change. Always 1 for inserts.
    pub rows: u32,
    pub bytes: usize,
    pub reasons: Vec<String>,
    pub confirm: bool,
    pub timeout_ms: u64,
}

impl Action {
    pub fn input_type(&self, name: &str) -> Option<&InputType> {
        self.inputs.iter().find(|(n, _)| n == name).map(|(_, t)| t)
    }
}

/// How one returned column appears to one requester.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Show {
    Full,
    Masked(Mask),
    Withheld,
}

#[derive(Debug, Clone)]
pub struct ColumnView {
    pub column: String,
    pub level: u8,
    pub show: Show,
}

/// One action as offered to one requester, with its SQL fixed in advance.
#[derive(Debug, Clone)]
pub struct MenuItem {
    pub action: usize,
    pub reasons: Vec<String>,
    pub view: Vec<ColumnView>,
    pub reply_level: u8,
    pub sql: String,
    /// Input names, in the order their values are bound to the SQL placeholders.
    pub params: Vec<String>,
}

pub enum Offer {
    Yes(MenuItem),
    No(String),
}

/// Reads, parses and checks a rules file, including against the real database.
pub fn load(path: &Path) -> Result<Rules, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if meta.len() > MAX_RULES_BYTES {
        return Err("the rules file is larger than 1 MB".into());
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let base = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let rules = parse(&text, &base)?;
    check_against_database(&rules)?;
    Ok(rules)
}

fn at(line: usize, msg: impl AsRef<str>) -> String {
    format!("line {line}: {}", msg.as_ref())
}

struct Block {
    line: usize,
    kind: &'static str,
    name: String,
    props: Vec<Prop>,
}

struct Prop {
    line: usize,
    key: String,
    value: String,
}

fn split_key(s: &str) -> (&str, &str) {
    match s.find(' ') {
        Some(i) => (&s[..i], s[i + 1..].trim()),
        None => (s, ""),
    }
}

fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && s.len() <= 64
}

fn is_action_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && s.len() <= 64
}

fn is_word(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn is_machine(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// Splits "a, b, c" into checked, unique words.
fn word_list(v: &str, line: usize, what: &str, check: fn(&str) -> bool) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for part in v.split(',') {
        let w = part.trim();
        if !check(w) {
            return Err(at(line, format!("'{w}' is not a valid {what}")));
        }
        if out.iter().any(|x| x == w) {
            return Err(at(line, format!("{what} '{w}' is listed twice")));
        }
        out.push(w.to_owned());
    }
    if out.is_empty() {
        return Err(at(line, format!("needs at least one {what}")));
    }
    Ok(out)
}

fn number<T: std::str::FromStr + PartialOrd + Copy + std::fmt::Display>(
    v: &str,
    line: usize,
    what: &str,
    min: T,
    max: T,
) -> Result<T, String> {
    let ok = !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) && !(v.len() > 1 && v.starts_with('0'));
    match v.parse::<T>() {
        Ok(n) if ok && n >= min && n <= max => Ok(n),
        _ => Err(at(line, format!("{what} must be a whole number from {min} to {max}"))),
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, line: usize, key: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(at(line, format!("'{key}' is set twice")));
    }
    *slot = Some(value);
    Ok(())
}

/// Parses rules text without touching the database. `base` is the folder that
/// relative file paths are resolved against.
pub fn parse(text: &str, base: &Path) -> Result<Rules, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut database: Option<PathBuf> = None;
    let mut audit: Option<PathBuf> = None;
    let mut blocks: Vec<Block> = Vec::new();
    let mut in_block = false;

    for (i, raw) in text.lines().enumerate() {
        let ln = i + 1;
        if raw.contains('\t') {
            return Err(at(ln, "tabs are not allowed, indent with spaces"));
        }
        if raw.chars().any(|c| c.is_control() || is_invisible(c)) {
            return Err(at(ln, "control or invisible characters are not allowed in rules"));
        }
        let line = raw.trim_end();
        let body = line.trim_start();
        if body.is_empty() || body.starts_with('#') {
            continue;
        }
        let indented = body.len() != line.len();
        let (key, value) = split_key(body);
        if indented {
            let block = match (in_block, blocks.last_mut()) {
                (true, Some(b)) => b,
                _ => return Err(at(ln, "this indented line is not inside a block")),
            };
            block.props.push(Prop { line: ln, key: key.to_owned(), value: value.to_owned() });
            continue;
        }
        match key {
            "database" | "audit" => {
                if value.is_empty() {
                    return Err(at(ln, format!("'{key}' needs a file path")));
                }
                let slot = if key == "database" { &mut database } else { &mut audit };
                set_once(slot, base.join(value), ln, key)?;
                in_block = false;
            }
            "levels" | "table" | "requester" | "action" => {
                let kind: &'static str = match key {
                    "levels" => "levels",
                    "table" => "table",
                    "requester" => "requester",
                    _ => "action",
                };
                let name_ok = match kind {
                    "levels" => value.is_empty(),
                    "table" => is_ident(value),
                    "requester" => is_word(value),
                    _ => is_action_name(value),
                };
                if !name_ok {
                    let hint = match kind {
                        "levels" => "'levels' takes no name",
                        "table" => "table names use letters, digits and underscores",
                        "requester" => "requester names use lowercase letters, digits, hyphens and underscores",
                        _ => "action names use lowercase letters, digits and underscores, starting with a letter",
                    };
                    return Err(at(ln, hint));
                }
                if blocks.iter().any(|b| b.kind == kind && b.name == value) {
                    let what = if kind == "levels" { "levels".to_owned() } else { format!("{kind} '{value}'") };
                    return Err(at(ln, format!("{what} is defined twice")));
                }
                blocks.push(Block { line: ln, kind, name: value.to_owned(), props: Vec::new() });
                in_block = true;
            }
            other => return Err(at(ln, format!("unknown word '{other}'"))),
        }
    }

    let database = database.ok_or("the rules must say which 'database' to guard")?;
    let audit = audit.ok_or("the rules must say where the 'audit' log lives")?;

    let levels = parse_levels(&blocks)?;
    let mut tables = BTreeMap::new();
    let mut requesters = Vec::new();
    let mut actions = Vec::new();
    for b in &blocks {
        match b.kind {
            "table" => {
                let t = parse_table(b, &levels)?;
                tables.insert(t.name.clone(), t);
            }
            "requester" => requesters.push(parse_requester(b, &levels)?),
            "action" => actions.push(parse_action(b)?),
            _ => {}
        }
    }
    if requesters.is_empty() {
        return Err("the rules define no requesters".into());
    }
    for (i, a) in requesters.iter().enumerate() {
        for b in &requesters[i + 1..] {
            if a.key_sha256 == b.key_sha256 {
                return Err(at(b.line, format!("requesters '{}' and '{}' share a key", a.name, b.name)));
            }
        }
    }
    if actions.is_empty() {
        return Err("the rules define no actions".into());
    }
    if tables.is_empty() {
        return Err("the rules define no tables".into());
    }
    for a in &actions {
        validate_action(a, &tables)?;
    }
    Ok(Rules { database, audit, levels, tables, requesters, actions })
}

fn parse_levels(blocks: &[Block]) -> Result<BTreeMap<u8, String>, String> {
    let block = blocks.iter().find(|b| b.kind == "levels").ok_or("the rules must define 'levels'")?;
    let mut levels = BTreeMap::new();
    for p in &block.props {
        let n: u8 = number(&p.key, p.line, "a level", 0, 9)?;
        if !is_word(&p.value) {
            return Err(at(p.line, "each level needs a one-word name, like: 1 basic"));
        }
        if levels.contains_key(&n) {
            return Err(at(p.line, format!("level {n} is defined twice")));
        }
        if levels.values().any(|v| v == &p.value) {
            return Err(at(p.line, format!("level name '{}' is used twice", p.value)));
        }
        levels.insert(n, p.value.clone());
    }
    if levels.is_empty() {
        return Err(at(block.line, "'levels' needs at least one level"));
    }
    Ok(levels)
}

fn level_ref(v: &str, line: usize, levels: &BTreeMap<u8, String>) -> Result<u8, String> {
    let n: u8 = number(v, line, "a level", 0, 9)?;
    if !levels.contains_key(&n) {
        return Err(at(line, format!("level {n} is not defined in 'levels'")));
    }
    Ok(n)
}

fn parse_table(b: &Block, levels: &BTreeMap<u8, String>) -> Result<Table, String> {
    let mut columns: Vec<(String, u8)> = Vec::new();
    let mut together = Vec::new();
    for p in &b.props {
        if p.key == "together" {
            let words: Vec<&str> = p.value.split_whitespace().collect();
            let n = words.len();
            let shape = "write it like: together zip + birthdate level 2";
            if n < 5 || words[n - 2] != "level" || (n - 2) % 2 == 0 {
                return Err(at(p.line, shape));
            }
            let mut cols: Vec<String> = Vec::new();
            for (j, w) in words[..n - 2].iter().enumerate() {
                if j % 2 == 1 {
                    if *w != "+" {
                        return Err(at(p.line, shape));
                    }
                } else if !is_ident(w) {
                    return Err(at(p.line, format!("'{w}' is not a column name")));
                } else if cols.iter().any(|c| c == w) {
                    return Err(at(p.line, format!("column '{w}' appears twice")));
                } else {
                    cols.push((*w).to_owned());
                }
            }
            let level = level_ref(words[n - 1], p.line, levels)?;
            together.push((p.line, Together { columns: cols, level }));
            continue;
        }
        if !is_ident(&p.key) {
            return Err(at(p.line, format!("'{}' is not a column name", p.key)));
        }
        let lv = p.value.strip_prefix("level ").map(str::trim);
        let Some(lv) = lv else {
            return Err(at(p.line, format!("write it like: {} level 1", p.key)));
        };
        if columns.iter().any(|(c, _)| c == &p.key) {
            return Err(at(p.line, format!("column '{}' is labeled twice", p.key)));
        }
        columns.push((p.key.clone(), level_ref(lv, p.line, levels)?));
    }
    if columns.is_empty() {
        return Err(at(b.line, format!("table '{}' labels no columns", b.name)));
    }
    let mut groups = Vec::new();
    for (line, t) in together {
        for c in &t.columns {
            if !columns.iter().any(|(x, _)| x == c) {
                return Err(at(line, format!("column '{c}' is not labeled in table '{}'", b.name)));
            }
        }
        groups.push(t);
    }
    Ok(Table { name: b.name.clone(), columns, together: groups })
}

fn parse_requester(b: &Block, levels: &BTreeMap<u8, String>) -> Result<Requester, String> {
    let mut key: Option<[u8; 32]> = None;
    let mut machines: Option<Option<Vec<String>>> = None;
    let mut clearance: Option<u8> = None;
    let mut reasons: Option<Vec<String>> = None;
    let mut budgets: Vec<Budget> = Vec::new();
    for p in &b.props {
        match p.key.as_str() {
            "key-sha256" => set_once(&mut key, parse_hash(&p.value, p.line)?, p.line, &p.key)?,
            "machines" => {
                let m = if p.value == "any" { None } else { Some(word_list(&p.value, p.line, "machine name", is_machine)?) };
                set_once(&mut machines, m, p.line, &p.key)?;
            }
            "clearance" => set_once(&mut clearance, level_ref(&p.value, p.line, levels)?, p.line, &p.key)?,
            "reasons" => set_once(&mut reasons, word_list(&p.value, p.line, "reason", is_word)?, p.line, &p.key)?,
            "budget" => {
                let bg = parse_budget(&p.value, p.line)?;
                if budgets.iter().any(|x| x.kind == bg.kind && x.window_secs == bg.window_secs) {
                    return Err(at(p.line, "this budget is set twice"));
                }
                budgets.push(bg);
            }
            other => return Err(at(p.line, format!("unknown setting '{other}' for a requester"))),
        }
    }
    let need = |what: &str| at(b.line, format!("requester '{}' needs '{what}'", b.name));
    Ok(Requester {
        name: b.name.clone(),
        line: b.line,
        key_sha256: key.ok_or_else(|| need("key-sha256"))?,
        machines: machines.ok_or_else(|| need("machines"))?,
        clearance: clearance.ok_or_else(|| need("clearance"))?,
        reasons: reasons.ok_or_else(|| need("reasons"))?,
        budgets,
    })
}

fn parse_hash(v: &str, line: usize) -> Result<[u8; 32], String> {
    if v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(at(line, "key-sha256 must be 64 hex characters (use: middleman hash-key)"));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&v[i * 2..i * 2 + 2], 16).map_err(|_| at(line, "bad hex"))?;
    }
    Ok(out)
}

fn parse_budget(v: &str, line: usize) -> Result<Budget, String> {
    let w: Vec<&str> = v.split_whitespace().collect();
    let shape = "write it like: budget calls 30 per minute, or: budget rows 500 per hour";
    if w.len() != 4 || w[2] != "per" {
        return Err(at(line, shape));
    }
    let kind = match w[0] {
        "calls" => BudgetKind::Calls,
        "rows" => BudgetKind::Rows,
        _ => return Err(at(line, shape)),
    };
    let window_secs = match w[3] {
        "minute" => 60,
        "hour" => 3600,
        "day" => 86400,
        _ => return Err(at(line, "budgets are per minute, hour or day")),
    };
    let limit = number(w[1], line, "a budget", 1u32, 10_000_000)?;
    Ok(Budget { kind, limit, window_secs })
}

fn parse_input(v: &str, line: usize) -> Result<(String, InputType), String> {
    let Some((name, spec)) = v.split_once(':') else {
        return Err(at(line, "write it like: input customer_id: integer 1..999999"));
    };
    let name = name.trim();
    if !is_action_name(name) {
        return Err(at(line, "input names use lowercase letters, digits and underscores"));
    }
    if name == "reason" {
        return Err(at(line, "'reason' is reserved, every request already carries one"));
    }
    let w: Vec<&str> = spec.split_whitespace().collect();
    let ty = match w.first().copied() {
        Some("integer") => {
            let range = w.get(1).filter(|_| w.len() == 2).ok_or_else(|| at(line, "write it like: integer 1..999999"))?;
            let (lo, hi) = range.split_once("..").ok_or_else(|| at(line, "write it like: integer 1..999999"))?;
            let parse_i = |s: &str| -> Result<i64, String> {
                let digits = s.strip_prefix('-').unwrap_or(s);
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(at(line, format!("'{s}' is not a whole number")));
                }
                s.parse().map_err(|_| at(line, format!("'{s}' is out of range")))
            };
            let (min, max) = (parse_i(lo)?, parse_i(hi)?);
            if min > max {
                return Err(at(line, "the range is backwards"));
            }
            InputType::Integer { min, max }
        }
        Some("text") => {
            if w.len() != 4 || w[2] != "max" {
                return Err(at(line, "write it like: text name max 40"));
            }
            let charset = Charset::parse(w[1]).ok_or_else(|| {
                at(line, format!("'{}' is not a character set (digits, alnum, name, email, phone, code, line)", w[1]))
            })?;
            InputType::Text { charset, max: number(w[3], line, "max", 1usize, 10_000)? }
        }
        Some("choice") => {
            let rest = spec.trim().strip_prefix("choice").unwrap_or("").trim();
            InputType::Choice(word_list(rest, line, "choice", is_word)?)
        }
        Some("date") if w.len() == 1 => InputType::Date,
        _ => return Err(at(line, "input types are: integer, text, choice, date")),
    };
    Ok((name.to_owned(), ty))
}

fn parse_action(b: &Block) -> Result<Action, String> {
    let mut about: Option<String> = None;
    let mut kind: Option<Kind> = None;
    let mut table: Option<String> = None;
    let mut inputs: Vec<(String, InputType)> = Vec::new();
    let mut wheres: Vec<Where> = Vec::new();
    let mut returns: Option<Vec<String>> = None;
    let mut sets: Vec<(String, String)> = Vec::new();
    let mut masks: BTreeMap<String, Mask> = BTreeMap::new();
    let mut order: Option<(String, bool)> = None;
    let mut rows: Option<u32> = None;
    let mut bytes: Option<usize> = None;
    let mut reasons: Option<Vec<String>> = None;
    let mut confirm: Option<bool> = None;
    let mut timeout: Option<u64> = None;

    for p in &b.props {
        let (ln, v) = (p.line, p.value.as_str());
        match p.key.as_str() {
            "about" => {
                if v.is_empty() || v.chars().count() > 500 {
                    return Err(at(ln, "'about' needs a description of up to 500 characters"));
                }
                set_once(&mut about, v.to_owned(), ln, "about")?;
            }
            "kind" => {
                let k = match v {
                    "read" => Kind::Read,
                    "insert" => Kind::Insert,
                    "update" => Kind::Update,
                    _ => return Err(at(ln, "kind is one of: read, insert, update")),
                };
                set_once(&mut kind, k, ln, "kind")?;
            }
            "table" => {
                if !is_ident(v) {
                    return Err(at(ln, "not a table name"));
                }
                set_once(&mut table, v.to_owned(), ln, "table")?;
            }
            "input" => {
                let (name, ty) = parse_input(v, ln)?;
                if inputs.iter().any(|(n, _)| n == &name) {
                    return Err(at(ln, format!("input '{name}' is declared twice")));
                }
                inputs.push((name, ty));
            }
            "where" => {
                let w: Vec<&str> = v.split_whitespace().collect();
                let op = (w.len() == 3).then(|| Op::parse(w[1])).flatten();
                let Some(op) = op else {
                    return Err(at(ln, "write it like: where id = customer_id (operators: = < <= > >=)"));
                };
                if !is_ident(w[0]) {
                    return Err(at(ln, format!("'{}' is not a column name", w[0])));
                }
                wheres.push(Where { column: w[0].to_owned(), op, input: w[2].to_owned() });
            }
            "returns" => set_once(&mut returns, word_list(v, ln, "column", is_ident)?, ln, "returns")?,
            "set" => {
                let w: Vec<&str> = v.split_whitespace().collect();
                if w.len() != 3 || w[1] != "=" || !is_ident(w[0]) {
                    return Err(at(ln, "write it like: set phone = phone"));
                }
                if sets.iter().any(|(c, _)| c == w[0]) {
                    return Err(at(ln, format!("column '{}' is set twice", w[0])));
                }
                sets.push((w[0].to_owned(), w[2].to_owned()));
            }
            "mask" => {
                let w: Vec<&str> = v.split_whitespace().collect();
                let mask = match w.as_slice() {
                    [_, "all"] => Mask::All,
                    [_, "last", n] => Mask::Last(number(n, ln, "the number of characters kept", 1usize, 8)?),
                    _ => return Err(at(ln, "write it like: mask ssn last 4, or: mask ssn all")),
                };
                if masks.insert(w[0].to_owned(), mask).is_some() {
                    return Err(at(ln, format!("column '{}' is masked twice", w[0])));
                }
            }
            "order" => {
                let w: Vec<&str> = v.split_whitespace().collect();
                let desc = match w.as_slice() {
                    [c, "asc"] if is_ident(c) => false,
                    [c, "desc"] if is_ident(c) => true,
                    _ => return Err(at(ln, "write it like: order id desc")),
                };
                set_once(&mut order, (w[0].to_owned(), desc), ln, "order")?;
            }
            "rows" => set_once(&mut rows, number(v, ln, "rows", 1u32, 1000)?, ln, "rows")?,
            "bytes" => set_once(&mut bytes, number(v, ln, "bytes", 256usize, 1_000_000)?, ln, "bytes")?,
            "timeout" => set_once(&mut timeout, number(v, ln, "timeout", 10u64, 30_000)?, ln, "timeout")?,
            "reasons" => set_once(&mut reasons, word_list(v, ln, "reason", is_word)?, ln, "reasons")?,
            "confirm" => {
                let c = match v {
                    "yes" => true,
                    "no" => false,
                    _ => return Err(at(ln, "confirm is yes or no")),
                };
                set_once(&mut confirm, c, ln, "confirm")?;
            }
            other => return Err(at(ln, format!("unknown setting '{other}' for an action"))),
        }
    }

    let need = |what: &str| at(b.line, format!("action '{}' needs '{what}'", b.name));
    let kind = kind.ok_or_else(|| need("kind"))?;
    let rows = match kind {
        Kind::Insert => {
            if rows.is_some() {
                return Err(at(b.line, format!("action '{}': inserts always add one row, remove 'rows'", b.name)));
            }
            1
        }
        _ => rows.ok_or_else(|| need("rows"))?,
    };
    Ok(Action {
        name: b.name.clone(),
        line: b.line,
        about: about.ok_or_else(|| need("about"))?,
        kind,
        table: table.ok_or_else(|| need("table"))?,
        inputs,
        wheres,
        returns: returns.unwrap_or_default(),
        sets,
        masks,
        order,
        rows,
        bytes: bytes.unwrap_or(16_384),
        reasons: reasons.ok_or_else(|| need("reasons"))?,
        confirm: confirm.unwrap_or(kind != Kind::Read),
        timeout_ms: timeout.unwrap_or(2_000),
    })
}

fn validate_action(a: &Action, tables: &BTreeMap<String, Table>) -> Result<(), String> {
    let e = |msg: String| at(a.line, format!("action '{}': {msg}", a.name));
    let t = tables.get(&a.table).ok_or_else(|| e(format!("table '{}' is not in the rules", a.table)))?;
    let col = |c: &str| -> Result<(), String> {
        t.level(c).map(|_| ()).ok_or_else(|| e(format!("column '{c}' is not labeled in table '{}'", t.name)))
    };
    let input = |i: &str| -> Result<(), String> {
        a.input_type(i).map(|_| ()).ok_or_else(|| e(format!("'{i}' is not one of its inputs")))
    };
    for w in &a.wheres {
        col(&w.column)?;
        input(&w.input)?;
    }
    for (c, i) in &a.sets {
        col(c)?;
        input(i)?;
    }
    for r in &a.returns {
        col(r)?;
    }
    if let Some((c, _)) = &a.order {
        col(c)?;
    }
    for m in a.masks.keys() {
        if !a.returns.contains(m) {
            return Err(e(format!("masks '{m}', which it does not return")));
        }
    }
    for (name, _) in &a.inputs {
        let used = a.wheres.iter().any(|w| &w.input == name) || a.sets.iter().any(|(_, i)| i == name);
        if !used {
            return Err(e(format!("input '{name}' is never used")));
        }
    }
    match a.kind {
        Kind::Read => {
            if a.returns.is_empty() {
                return Err(e("a read must say what it 'returns'".into()));
            }
            if !a.sets.is_empty() {
                return Err(e("a read cannot 'set' anything".into()));
            }
        }
        Kind::Insert | Kind::Update => {
            if a.sets.is_empty() {
                return Err(e(format!("an {} must 'set' at least one column", a.kind.word())));
            }
            if !a.returns.is_empty() || a.order.is_some() || !a.masks.is_empty() {
                return Err(e("only reads use 'returns', 'order' and 'mask'".into()));
            }
            if a.kind == Kind::Insert && !a.wheres.is_empty() {
                return Err(e("an insert cannot have 'where'".into()));
            }
            if a.kind == Kind::Update && a.wheres.is_empty() {
                return Err(e("an update needs at least one 'where', so it can never change every row".into()));
            }
        }
    }
    Ok(())
}

/// Every table named in the rules must exist, every one of its columns must have a level,
/// and every labeled column must exist. A new, unlabeled column stops the middleman
/// until someone decides how sensitive it is.
pub fn check_against_database(rules: &Rules) -> Result<(), String> {
    if !rules.database.is_file() {
        return Err(format!("database file {} does not exist", rules.database.display()));
    }
    let conn = Connection::open_with_flags(&rules.database, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("cannot open database: {e}"))?;
    for t in rules.tables.values() {
        let mut stmt = conn
            .prepare("SELECT name FROM pragma_table_info(?1)")
            .map_err(|e| format!("cannot read the database schema: {e}"))?;
        let cols: Vec<String> = stmt
            .query_map([&t.name], |r| r.get(0))
            .and_then(|rows| rows.collect())
            .map_err(|e| format!("cannot read the database schema: {e}"))?;
        if cols.is_empty() {
            return Err(format!("table '{}' is in the rules but not in the database", t.name));
        }
        for c in &cols {
            if t.level(c).is_none() {
                return Err(format!(
                    "column {}.{c} exists in the database but has no level in the rules; every column must be labeled",
                    t.name
                ));
            }
        }
        for (c, _) in &t.columns {
            if !cols.contains(c) {
                return Err(format!("column {}.{c} is in the rules but not in the database", t.name));
            }
        }
    }
    Ok(())
}

fn quote(ident: &str) -> String {
    format!("\"{ident}\"")
}

impl Rules {
    pub fn level_name(&self, level: u8) -> &str {
        self.levels.get(&level).map(String::as_str).unwrap_or("?")
    }

    /// Decides whether `req` may use action number `idx`, and if so exactly what it sees.
    pub fn offer(&self, req: &Requester, idx: usize) -> Offer {
        let a = &self.actions[idx];
        let t = &self.tables[&a.table];
        let clr = req.clearance;
        let lvl = |c: &str| t.level(c).unwrap_or(u8::MAX);

        // Filtering or sorting by a column reveals things about it, even if the column is
        // never returned. So it needs the same clearance as reading that column, and the
        // reply carries that column's level.
        let filter_level = a
            .wheres
            .iter()
            .map(|w| lvl(&w.column))
            .chain(a.order.iter().map(|(c, _)| lvl(c)))
            .max()
            .unwrap_or(0);
        if filter_level > clr {
            return Offer::No(format!(
                "filters or sorts by a level {filter_level} column, clearance is {clr}"
            ));
        }
        if a.kind != Kind::Read {
            let write_level = a.sets.iter().map(|(c, _)| lvl(c)).max().unwrap_or(0);
            if write_level > clr {
                return Offer::No(format!("writes a level {write_level} column, clearance is {clr}"));
            }
        }

        let reasons: Vec<String> = a.reasons.iter().filter(|r| req.reasons.contains(r)).cloned().collect();
        if reasons.is_empty() {
            return Offer::No("no reason in common with this requester".into());
        }

        let mut view = Vec::new();
        let mut reply_level = filter_level;
        let mut params: Vec<String> = Vec::new();
        let sql = match a.kind {
            Kind::Read => {
                for c in &a.returns {
                    let level = lvl(c);
                    let show = if level <= clr {
                        Show::Full
                    } else if let Some(m) = a.masks.get(c) {
                        Show::Masked(*m)
                    } else {
                        Show::Withheld
                    };
                    view.push(ColumnView { column: c.clone(), level, show });
                }
                // Fields that are harmless alone can identify someone together. If a group is
                // above clearance, keep only its first column.
                for g in &t.together {
                    let visible = |view: &Vec<ColumnView>, c: &String| {
                        view.iter().any(|v| &v.column == c && v.show != Show::Withheld)
                    };
                    if g.level > clr && g.columns.iter().all(|c| visible(&view, c)) {
                        for c in g.columns.iter().skip(1) {
                            if let Some(v) = view.iter_mut().find(|v| &v.column == c) {
                                v.show = Show::Withheld;
                            }
                        }
                    }
                }
                if view.iter().all(|v| v.show == Show::Withheld) {
                    return Offer::No("every column it returns is above clearance".into());
                }
                for v in &view {
                    reply_level = reply_level.max(match v.show {
                        Show::Full => v.level,
                        Show::Masked(_) => v.level.min(clr),
                        Show::Withheld => 0,
                    });
                }
                for g in &t.together {
                    let all = g
                        .columns
                        .iter()
                        .all(|c| view.iter().any(|v| &v.column == c && v.show != Show::Withheld));
                    if all {
                        reply_level = reply_level.max(g.level.min(clr));
                    }
                }
                let cols: Vec<String> =
                    view.iter().filter(|v| v.show != Show::Withheld).map(|v| quote(&v.column)).collect();
                let mut sql = format!("SELECT {} FROM {}", cols.join(", "), quote(&t.name));
                push_where(&mut sql, &a.wheres, &mut params);
                if let Some((c, desc)) = &a.order {
                    sql.push_str(&format!(" ORDER BY {} {}", quote(c), if *desc { "DESC" } else { "ASC" }));
                }
                sql.push_str(&format!(" LIMIT {}", a.rows));
                sql
            }
            Kind::Insert | Kind::Update => {
                if a.kind == Kind::Insert {
                    let cols: Vec<String> = a.sets.iter().map(|(c, _)| quote(c)).collect();
                    let marks: Vec<String> = (1..=a.sets.len()).map(|n| format!("?{n}")).collect();
                    params.extend(a.sets.iter().map(|(_, i)| i.clone()));
                    format!("INSERT INTO {} ({}) VALUES ({})", quote(&t.name), cols.join(", "), marks.join(", "))
                } else {
                    let mut assigns = Vec::new();
                    for (c, i) in &a.sets {
                        params.push(i.clone());
                        assigns.push(format!("{} = ?{}", quote(c), params.len()));
                    }
                    let mut sql = format!("UPDATE {} SET {}", quote(&t.name), assigns.join(", "));
                    push_where(&mut sql, &a.wheres, &mut params);
                    sql
                }
            }
        };
        Offer::Yes(MenuItem { action: idx, reasons, view, reply_level, sql, params })
    }

    pub fn menu(&self, req: &Requester) -> Vec<MenuItem> {
        (0..self.actions.len())
            .filter_map(|i| match self.offer(req, i) {
                Offer::Yes(m) => Some(m),
                Offer::No(_) => None,
            })
            .collect()
    }
}

fn push_where(sql: &mut String, wheres: &[Where], params: &mut Vec<String>) {
    for (n, w) in wheres.iter().enumerate() {
        params.push(w.input.clone());
        sql.push_str(if n == 0 { " WHERE " } else { " AND " });
        sql.push_str(&format!("{} {} ?{}", quote(&w.column), w.op.sql(), params.len()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const KEY2: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn base(extra: &str) -> String {
        format!(
            "database shop.db\naudit audit.db\n\nlevels\n  0 public\n  1 basic\n  2 sensitive\n  3 restricted\n\n\
             table customers\n  id level 0\n  name level 1\n  zip level 1\n  birthdate level 1\n  ssn level 3\n  \
             together zip + birthdate level 2\n\n\
             requester low\n  key-sha256 {KEY}\n  machines any\n  clearance 1\n  reasons support\n\n\
             requester high\n  key-sha256 {KEY2}\n  machines any\n  clearance 3\n  reasons support, audit\n\n{extra}"
        )
    }

    const READ: &str = "action read_customer\n  about Read one.\n  kind read\n  table customers\n  \
                        input customer_id: integer 1..99\n  where id = customer_id\n  \
                        returns name, zip, birthdate, ssn\n  mask ssn last 4\n  rows 1\n  reasons support\n";

    fn rules(extra: &str) -> Result<Rules, String> {
        parse(&base(extra), Path::new("."))
    }

    #[test]
    fn a_good_file_parses() {
        let r = rules(READ).unwrap();
        assert_eq!(r.actions.len(), 1);
        assert_eq!(r.requesters.len(), 2);
    }

    #[test]
    fn mistakes_stop_the_file() {
        let bad = [
            (READ.replace("returns", "retruns"), "unknown setting 'retruns'"),
            (READ.replace("  rows 1\n", ""), "needs 'rows'"),
            (READ.replace("where id = customer_id", "where id = nobody"), "not one of its inputs"),
            (READ.replace("where id = customer_id", "where id == customer_id"), "write it like: where"),
            (READ.replace("mask ssn", "mask phone"), "masks 'phone'"),
            (READ.replace("returns name", "returns nickname"), "column 'nickname' is not labeled"),
            (READ.replace("table customers\n  input", "table orders\n  input"), "table 'orders' is not in the rules"),
            (format!("{READ}{READ}"), "defined twice"),
            (READ.replace("  about", "\tabout"), "tabs are not allowed"),
            (READ.replace("Read one.", "Read one.\u{200B}"), "invisible"),
            (READ.replace("input customer_id: integer 1..99\n  where id = customer_id\n", "input customer_id: integer 1..99\n"), "never used"),
        ];
        for (text, expected) in bad {
            let err = rules(&text).unwrap_err();
            assert!(err.contains(expected), "expected '{expected}', got '{err}'");
        }
    }

    #[test]
    fn updates_must_be_targeted() {
        let upd = "action wipe\n  about Bad.\n  kind update\n  table customers\n  input n: text name max 9\n  \
                   set name = n\n  rows 1\n  reasons support\n";
        assert!(rules(upd).unwrap_err().contains("can never change every row"));
    }

    #[test]
    fn levels_masks_and_groups_shape_the_view() {
        let r = rules(READ).unwrap();
        let low = &r.requesters[0];
        let Offer::Yes(m) = r.offer(low, 0) else { panic!("should be offered") };
        let show = |c: &str| m.view.iter().find(|v| v.column == c).unwrap().show;
        assert_eq!(show("name"), Show::Full);
        assert_eq!(show("zip"), Show::Full);
        assert_eq!(show("birthdate"), Show::Withheld, "zip + birthdate together is level 2");
        assert_eq!(show("ssn"), Show::Masked(Mask::Last(4)));
        assert_eq!(m.reply_level, 1);
        assert!(!m.sql.contains("birthdate"), "withheld columns are never even fetched");

        let high = &r.requesters[1];
        let Offer::Yes(m) = r.offer(high, 0) else { panic!() };
        assert!(m.view.iter().all(|v| v.show == Show::Full));
        assert_eq!(m.reply_level, 3);
    }

    #[test]
    fn filtering_by_a_secret_column_needs_clearance_for_it() {
        let find = "action find_by_ssn\n  about Find.\n  kind read\n  table customers\n  \
                    input ssn: text code max 11\n  where ssn = ssn\n  returns id\n  rows 1\n  reasons support\n";
        let r = rules(find).unwrap();
        assert!(matches!(r.offer(&r.requesters[0], 0), Offer::No(why) if why.contains("level 3")));
        let Offer::Yes(m) = r.offer(&r.requesters[1], 0) else { panic!() };
        assert_eq!(m.reply_level, 3, "a match on ssn reveals level 3 information");
    }

    #[test]
    fn sql_is_built_from_rules_only() {
        let r = rules(READ).unwrap();
        let Offer::Yes(m) = r.offer(&r.requesters[1], 0) else { panic!() };
        assert_eq!(
            m.sql,
            "SELECT \"name\", \"zip\", \"birthdate\", \"ssn\" FROM \"customers\" WHERE \"id\" = ?1 LIMIT 1"
        );
        assert_eq!(m.params, vec!["customer_id".to_owned()]);
    }
}
