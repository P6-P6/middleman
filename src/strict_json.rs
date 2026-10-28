//! The front door. Two jobs, both done before anything else looks at a request:
//!
//! 1. **Size gate.** A message is measured while it is read. Anything over the cap is
//!    discarded without ever being parsed.
//! 2. **Strict parse.** JSON with duplicate keys, trailing garbage or broken escapes is
//!    refused. Duplicate keys matter because two programs can disagree about which copy
//!    wins, and that disagreement is a classic way to smuggle a value past a checker.

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;
use std::io::{self, BufRead};

/// One newline-delimited frame read from a stream.
#[derive(Debug, PartialEq)]
pub enum Frame {
    Line(Vec<u8>),
    TooLarge,
    Eof,
}

/// Reads one line, but never holds more than `max` bytes of it in memory.
/// A line longer than `max` is skipped to its end and reported as `TooLarge`.
pub fn read_frame<R: BufRead>(r: &mut R, max: usize) -> io::Result<Frame> {
    let mut buf: Vec<u8> = Vec::new();
    let mut too_large = false;
    let mut saw_any = false;
    loop {
        let (consumed, done) = {
            let avail = r.fill_buf()?;
            if avail.is_empty() {
                if too_large {
                    return Ok(Frame::TooLarge);
                }
                return Ok(if saw_any { Frame::Line(strip_cr(buf)) } else { Frame::Eof });
            }
            saw_any = true;
            let newline = avail.iter().position(|&b| b == b'\n');
            let chunk = match newline {
                Some(i) => &avail[..i],
                None => avail,
            };
            if !too_large {
                if buf.len() + chunk.len() > max {
                    too_large = true;
                    buf = Vec::new();
                } else {
                    buf.extend_from_slice(chunk);
                }
            }
            match newline {
                Some(i) => (i + 1, true),
                None => (avail.len(), false),
            }
        };
        r.consume(consumed);
        if done {
            return Ok(if too_large { Frame::TooLarge } else { Frame::Line(strip_cr(buf)) });
        }
    }
}

fn strip_cr(mut v: Vec<u8>) -> Vec<u8> {
    if v.last() == Some(&b'\r') {
        v.pop();
    }
    v
}

/// Parses JSON and refuses duplicate object keys at any depth.
pub fn parse(bytes: &[u8]) -> Result<Value, String> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let Strict(v) = Strict::deserialize(&mut de).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(v)
}

struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("number out of range"))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        Strict::deserialize(d).map(|s| s.0)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(Strict(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(de::Error::custom("duplicate key"));
            }
            let Strict(v) = map.next_value()?;
            out.insert(key, v);
        }
        Ok(Value::Object(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn duplicate_keys_are_refused_at_any_depth() {
        assert!(parse(br#"{"a":1,"a":2}"#).is_err());
        assert!(parse(br#"{"x":{"a":1,"a":2}}"#).is_err());
        assert!(parse(br#"[{"a":1},{"a":2}]"#).is_ok());
    }

    #[test]
    fn trailing_garbage_and_broken_escapes_are_refused() {
        assert!(parse(br#"{"a":1} {"b":2}"#).is_err());
        assert!(parse(br#"{"a":"\ud800"}"#).is_err());
        assert!(parse(b"{\"a\":1,}").is_err());
    }

    #[test]
    fn size_gate_skips_long_lines_and_keeps_going() {
        let data = format!("{}\nshort\n", "x".repeat(100));
        let mut r = Cursor::new(data.into_bytes());
        assert_eq!(read_frame(&mut r, 10).unwrap(), Frame::TooLarge);
        assert_eq!(read_frame(&mut r, 10).unwrap(), Frame::Line(b"short".to_vec()));
        assert_eq!(read_frame(&mut r, 10).unwrap(), Frame::Eof);
    }

    #[test]
    fn size_gate_handles_crlf_and_missing_final_newline() {
        let mut r = Cursor::new(b"one\r\ntwo".to_vec());
        assert_eq!(read_frame(&mut r, 10).unwrap(), Frame::Line(b"one".to_vec()));
        assert_eq!(read_frame(&mut r, 10).unwrap(), Frame::Line(b"two".to_vec()));
        assert_eq!(read_frame(&mut r, 10).unwrap(), Frame::Eof);
    }
}
