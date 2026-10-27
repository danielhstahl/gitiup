//! The canonicaliser: JSON bytes with exactly one encoding per document.
//!
//! This module *is* the reason ADR-0001 exists. A signature is only worth
//! anything if a verifier three years from now, in another language, can rebuild
//! the signed bytes byte for byte from the document it was handed. `serde_json`
//! will not do that: it preserves map order, accepts duplicate keys (last one
//! wins), happily emits `1.0` for a float, and accepts `\u0041` as `A`. Each of
//! those is a second encoding of the same document, which means a second digest,
//! which means a signature that verifies against bytes the verifier never saw.
//!
//! So the format gets its own encoder *and* its own strict reader
//! ([`from_bytes`]), and "is this the canonical form?" is a checkable property
//! ([`is_canonical`]) rather than an assumption.
//!
//! # The rules (RFC 8785, narrowed)
//!
//! The encoding is
//! [RFC 8785 (JSON Canonicalization Scheme)](https://datatracker.ietf.org/doc/html/rfc8785)
//! restricted to what this format actually needs. The narrowing is deliberate; each cut removes a place where
//! two honest implementations disagree.
//!
//! | # | rule | why it is not plain `serde_json` |
//! |---|------|----------------------------------|
//! | 1 | object keys sorted by Unicode scalar value, written without whitespace | map order otherwise leaks into the digest |
//! | 2 | **integers only**, `i64`, no `-0`, no fraction, no exponent | cross-language float rendering is a swamp; ADR-0001 D1 bans floats outright |
//! | 3 | duplicate keys are an error, not last-wins | two interpretations of one byte string is an attack surface |
//! | 4 | escapes limited to `\" \\ \b \t \n \f \r` and `\u00xx` (lower-case hex) for the remaining controls; everything else raw UTF-8 | `\u0041` and `\u00e9` are second encodings of `A` and `é` |
//! | 5 | no `null` anywhere; an absent field is an omitted key | `null` vs absent is a whole class of "which did the signer sign?" |
//! | 6 | keys strictly ascending ⇒ duplicates and mis-ordering both fail on read | makes the reader itself prove rule 1 |
//! | 7 | depth ≤ [`MAX_DEPTH`], size ≤ [`MAX_ENCODED_BYTES`], no `\/`, no leading/trailing whitespace, no BOM | a volunteer verifier must be able to bound its work |
//!
//! RFC 8785 sorts by UTF-16 code unit; that ordering and UTF-8 byte order agree
//! for every well-formed string, and the strings that would tell them apart
//! (lone surrogates) cannot be built in Rust and are rejected on read. So "sorted
//! by bytes" below *is* the RFC's ordering.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::error::{Error, Result};

/// Maximum number of nested containers (arrays and objects) accepted by the
/// reader and the writer.
pub const MAX_DEPTH: usize = 32;

/// Maximum size of a canonical document (1 MiB).
///
/// A manifest holds digests and short strings, never logs or artifacts, so a
/// megabyte is orders of magnitude above honest use while still bounding what a
/// volunteer verifier has to buffer ([ADR-0001 D7](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).
pub const MAX_ENCODED_BYTES: usize = 1024 * 1024;

/// Canonical bytes of anything serializable.
///
/// Floats and `null`s produce an error rather than a surprise; use a digest or
/// omit the field instead.
pub fn to_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let json = serde_json::to_value(value)
        .map_err(|e| Error::invalid("canonical encode", e.to_string()))?;
    to_value_bytes(&json)
}

/// Deserialize `T` from canonical bytes only; non-canonical input is refused with
/// [`ErrorKind::DigestMismatch`](crate::error::ErrorKind::DigestMismatch) so a
/// transport bug is never mistaken for a different attestation.
pub fn from_bytes<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let value = read_canonical(bytes)?;
    serde_json::from_value(value).map_err(|e| Error::invalid("manifest", e.to_string()))
}

/// Canonical bytes of an already-parsed [`Value`].
pub fn to_value_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_value(&mut out, value, 0)?;
    if out.len() > MAX_ENCODED_BYTES {
        return Err(Error::invalid(
            "canonical encode",
            format!(
                "{} bytes exceeds the {} byte limit",
                out.len(),
                MAX_ENCODED_BYTES
            ),
        ));
    }
    Ok(out)
}

/// Parse bytes that **must** already be canonical, and return the [`Value`].
///
/// This is a deliberately strict JSON reader: anything that a lenient parser
/// would forgive (whitespace, duplicate keys, `1.0`, `NaN`, `\u0041`, `\/`, a
/// trailing newline) is an error here.
pub fn read_canonical(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > MAX_ENCODED_BYTES {
        return Err(Error::invalid(
            "canonical read",
            format!(
                "{} bytes exceeds the {} byte limit",
                bytes.len(),
                MAX_ENCODED_BYTES
            ),
        ));
    }
    if bytes.first() == Some(&0xef) {
        return Err(Error::invalid(
            "canonical read",
            "input starts with a UTF-8 BOM",
        ));
    }
    let mut reader = Reader { b: bytes, i: 0 };
    let value = reader.value(0)?;
    if reader.i != bytes.len() {
        return Err(reader.err(bytes, reader.i, "trailing data after the top-level value"));
    }
    Ok(value)
}

/// Read bytes that must be canonical, reporting a failure as
/// [`ErrorKind::DigestMismatch`](crate::error::ErrorKind::DigestMismatch).
///
/// The distinction matters for `gitiup verify`: "these bytes are not the bytes
/// that were signed" is a different verdict from "this document is malformed", and
/// the exit codes are different too (8 and 6).
pub fn require_canonical(bytes: &[u8]) -> Result<Value> {
    read_canonical(bytes).map_err(|e| {
        Error::new(
            crate::error::ErrorKind::DigestMismatch,
            "canonical form",
            format!("{}: {}", e.context(), e.detail()),
        )
        .with_hint(
            "the stored or received payload must be the canonical encoding, byte for byte;              a transport that re-serializes JSON has broken the signature",
        )
    })
}

/// True when `bytes` is *the* canonical encoding of the document they hold.
///
/// Checks both directions: the strict reader must accept them, and re-encoding
/// what it read must reproduce them exactly.
pub fn is_canonical(bytes: &[u8]) -> bool {
    match read_canonical(bytes) {
        Ok(value) => to_value_bytes(&value).is_ok_and(|again| again == bytes),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------- writing ---
//
// Writing is done into a `Vec<u8>` and cannot fail: the only fallible step is
// deciding what a `Value` means (floats, null), and that is an error we report.

fn write_value(out: &mut Vec<u8>, value: &Value, depth: usize) -> Result<()> {
    if depth >= MAX_DEPTH {
        return Err(Error::invalid(
            "canonical encode",
            format!("nesting deeper than {MAX_DEPTH}"),
        ));
    }
    match value {
        Value::Null => {
            return Err(Error::invalid(
                "canonical encode",
                "null is not used by this format: omit the field instead",
            ));
        }
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => {
            // No floats, ever. A value that arrived as f64 is rejected rather
            // than rendered, because `1.0` vs `1` vs `1e0` would then decide the
            // digest.
            if let Some(v) = number.as_i64() {
                out.extend_from_slice(v.to_string().as_bytes());
            } else if let Some(v) = number.as_u64() {
                if v > i64::MAX as u64 {
                    return Err(Error::invalid(
                        "canonical encode",
                        format!("{v} does not fit in i64"),
                    ));
                }
                out.extend_from_slice(v.to_string().as_bytes());
            } else {
                return Err(Error::invalid(
                    "canonical encode",
                    format!(
                        "non-integer number {number}: express quantities as integers (microseconds, bytes) or as a digest"
                    ),
                ));
            }
        }
        Value::String(string) => write_string(out, string),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(out, item, depth + 1)?;
            }
            out.push(b']');
        }
        Value::Object(map) => write_object(out, map, depth)?,
    }
    Ok(())
}

fn write_object(out: &mut Vec<u8>, map: &Map<String, Value>, depth: usize) -> Result<()> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_unstable();
    out.push(b'{');
    for (i, key) in keys.into_iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        write_string(out, key);
        out.push(b':');
        write_value(out, &map[key], depth + 1)?;
    }
    out.push(b'}');
    Ok(())
}

/// Write one JSON string with the escape set of rule 4.
fn write_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{09}' => out.extend_from_slice(b"\\t"),
            '\u{0a}' => out.extend_from_slice(b"\\n"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\u{0d}' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                let mut buf = [0u8; 6];
                let hex = b"0123456789abcdef";
                let code = c as u32;
                buf[..4].copy_from_slice(b"\\u00");
                buf[4] = hex[(code >> 4) as usize];
                buf[5] = hex[(code & 0xf) as usize];
                out.extend_from_slice(&buf);
            }
            // Everything from U+0020 up goes out as raw UTF-8, including
            // non-ASCII: `\u00e9` would be a second encoding of `é`.
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

// ---------------------------------------------------------------- reading ---

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn err(&self, bytes: &[u8], at: usize, what: &str) -> Error {
        Error::invalid(
            "canonical read",
            format!(
                "{what} at byte {} of {} of the canonical form",
                at,
                bytes.len()
            ),
        )
        .with_hint("the signed bytes must be the canonical encoding, byte for byte")
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn expect(&mut self, byte: u8, what: &str) -> Result<()> {
        if self.peek() == Some(byte) {
            self.i += 1;
            Ok(())
        } else {
            Err(self.err(self.b, self.i, what))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value> {
        if depth >= MAX_DEPTH {
            return Err(Error::invalid(
                "canonical read",
                format!("nesting deeper than {MAX_DEPTH}"),
            ));
        }
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            // `null` is not part of the format (rule 5).
            Some(b'n') => Err(self.err(self.b, self.i, "null is not used by this format")),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(c) if c <= b' ' => Err(self.err(self.b, self.i, "whitespace is not canonical")),
            Some(_) => Err(self.err(self.b, self.i, "unexpected byte")),
            None => Err(self.err(self.b, self.i, "input ended unexpectedly")),
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(value)
        } else {
            Err(self.err(self.b, self.i, "expected a literal"))
        }
    }

    fn number(&mut self) -> Result<Value> {
        let start = self.i;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.i += 1;
        }
        let digits_start = self.i;
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.i += 1;
        }
        let digits = &self.b[digits_start..self.i];
        if digits.is_empty() {
            return Err(self.err(self.b, start, "expected an integer"));
        }
        if digits.len() > 1 && digits[0] == b'0' {
            return Err(self.err(self.b, start, "leading zeros are not canonical"));
        }
        if negative && digits == b"0" {
            return Err(self.err(self.b, start, "-0 is not canonical"));
        }
        if matches!(self.peek(), Some(b'.') | Some(b'e') | Some(b'E')) {
            return Err(self.err(
                self.b,
                start,
                "non-integer numbers are not used by this format",
            ));
        }
        let text = std::str::from_utf8(&self.b[start..self.i])
            .map_err(|_| self.err(self.b, start, "not ASCII digits"))?;
        text.parse::<i64>()
            .map(Value::from)
            .map_err(|_| self.err(self.b, start, "integer out of the i64 range"))
    }

    fn string(&mut self) -> Result<String> {
        self.expect(b'"', "expected a string")?;
        let mut out = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(self.err(self.b, self.i, "unterminated string"));
            };
            self.i += 1;
            match byte {
                b'"' => return Ok(out),
                b'\\' => {
                    let Some(esc) = self.peek() else {
                        return Err(self.err(self.b, self.i, "unterminated escape"));
                    };
                    self.i += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        // `\/` is legal JSON but is a second encoding of `/`.
                        b'/' => {
                            return Err(self.err(self.b, self.i - 2, "\\/ is not canonical"));
                        }
                        b'u' => out.push(self.escaped_control_unit()?),
                        _ => return Err(self.err(self.b, self.i - 1, "unknown escape")),
                    }
                }
                c if c < 0x20 => {
                    return Err(self.err(self.b, self.i - 1, "raw control byte needs an escape"));
                }
                c => {
                    // Copy the whole UTF-8 sequence started by this byte.
                    let len = utf8_len(c)
                        .ok_or_else(|| self.err(self.b, self.i - 1, "byte is not valid UTF-8"))?;
                    let end = self.i + len - 1;
                    if end > self.b.len() {
                        return Err(self.err(self.b, self.i - 1, "truncated UTF-8 sequence"));
                    }
                    let chunk = &self.b[self.i - 1..end];
                    let text = std::str::from_utf8(chunk)
                        .map_err(|_| self.err(self.b, self.i - 1, "byte is not valid UTF-8"))?;
                    out.push_str(text);
                    self.i = end;
                }
            }
        }
    }

    /// `\u00xx`, restricted to control characters the short escapes do not cover.
    fn escaped_control_unit(&mut self) -> Result<char> {
        let hex = self
            .b
            .get(self.i..self.i + 4)
            .ok_or_else(|| self.err(self.b, self.i, "truncated \\u escape"))?;
        let text = std::str::from_utf8(hex)
            .map_err(|_| self.err(self.b, self.i, "\\u escape needs four hex digits"))?;
        if text.chars().any(|c| !matches!(c, '0'..='9' | 'a'..='f')) {
            return Err(self.err(
                self.b,
                self.i,
                "\\u escape must be four *lower-case* hex digits, and only for control characters",
            ));
        }
        self.i += 4;
        let unit = u32::from_str_radix(text, 16).expect("validated hex");
        let allowed = unit < 0x20 && !matches!(unit, 0x08 | 0x09 | 0x0a | 0x0c | 0x0d);
        if !allowed {
            return Err(self.err(
                self.b,
                self.i - 6,
                &format!("\\u{text} is not a canonical escape (only controls below U+0020)"),
            ));
        }
        // U+0000..U+001F is always a valid scalar value.
        Ok(char::from_u32(unit).expect("control scalar"))
    }

    fn array(&mut self, depth: usize) -> Result<Value> {
        self.expect(b'[', "expected `[`")?;
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.err(self.b, self.i, "expected `,` or `]`")),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value> {
        self.expect(b'{', "expected `{`")?;
        let mut map = Map::new();
        let mut previous: Option<String> = None;
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Object(map));
        }
        loop {
            let key = self.string()?;
            // Rule 1 + rule 3 in one check: keys must strictly ascend, so a
            // duplicate (or a reordered) object never parses.
            if let Some(prev) = &previous
                && prev.as_bytes() >= key.as_bytes()
            {
                let what = if prev == &key {
                    "duplicate object key"
                } else {
                    "object keys must be sorted ascending"
                };
                return Err(self.err(self.b, self.i, what));
            }
            previous = Some(key.clone());
            self.expect(b':', "expected `:` after the key")?;
            map.insert(key, self.value(depth + 1)?);
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Object(map));
                }
                _ => return Err(self.err(self.b, self.i, "expected `,` or `}`")),
            }
        }
    }
}

/// Length of the UTF-8 sequence started by `first`, if it is a valid start.
fn utf8_len(first: u8) -> Option<usize> {
    match first {
        0x00..=0x7f => Some(1),
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        // Continuation bytes, overlong starters (0xc0/0xc1) and >U+10FFFF (0xf5+).
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::json;

    #[test]
    fn encodes_known_shapes() {
        assert_eq!(to_value_bytes(&json!(1)).unwrap(), b"1");
        assert_eq!(to_value_bytes(&json!(-0i64)).unwrap(), b"0");
        assert_eq!(
            to_value_bytes(&json!("é\n")).unwrap(),
            "\"é\\n\"".as_bytes()
        );
        assert_eq!(
            to_value_bytes(&json!({"b": 1, "a": 2})).unwrap(),
            br#"{"a":2,"b":1}"#
        );
        assert_eq!(to_value_bytes(&json!([])).unwrap(), b"[]");
        assert_eq!(to_value_bytes(&json!({})).unwrap(), b"{}");
        assert_eq!(
            to_value_bytes(&json!({"k": [1, 2, { "z": null }]}))
                .unwrap_err()
                .detail(),
            "null is not used by this format: omit the field instead"
        );
    }

    #[test]
    fn escapes_exactly_as_rfc8785() {
        let s = "\u{00}\u{07}\u{08}\t\n\u{0b}\u{0c}\r\u{1f}\"\\é";
        let got = String::from_utf8(to_value_bytes(&json!(s)).unwrap()).unwrap();
        assert_eq!(got, r#""\u0000\u0007\b\t\n\u000b\f\r\u001f\"\\é""#);
        assert!(is_canonical(got.as_bytes()));
    }

    #[test]
    fn rejects_floats() {
        for bad in [json!(1.0), json!(0.1), json!([1e3]), json!({"x": -0.5})] {
            let err = to_value_bytes(&bad).unwrap_err();
            assert!(err.detail().contains("non-integer"), "{bad:?} → {err}");
        }
    }

    #[test]
    fn round_trips_and_detects_canonical_form() {
        let value = json!({"b": [1, 2], "a": "x", "c": {"n": -3}});
        let bytes = to_value_bytes(&value).unwrap();
        assert!(is_canonical(&bytes));
        assert_eq!(read_canonical(&bytes).unwrap(), value);
    }

    #[test]
    fn reader_refuses_every_lenient_shortcut() {
        let bad: &[&str] = &[
            "",
            " ",
            " {}",
            "{} ",
            "{ }",
            "{\"a\" : 1}",
            "{\"a\":1,\"a\":2}",
            "{\"b\":1,\"a\":2}",
            "{\"a\":01}",
            "{\"a\":-0}",
            "{\"a\":1.0}",
            "{\"a\":1e3}",
            "{\"a\":NaN}",
            "{\"a\":+1}",
            "{\"a\":\"\\u0041\"}",
            "{\"a\":\"\\u00E9\"}",
            "{\"a\":\"\\u00e9\"}",
            "{\"a\":\"\\/\"}",
            "{\"a\":\"h\u{1}llo\"}",
            "{\"a\":\"\\u004",
            "[1,]",
            "{\"a\":1,}",
            "'x'",
            "tru",
            "{\"a\":[1,]}",
        ];
        for case in bad {
            assert!(!is_canonical(case.as_bytes()), "must be refused: {case:?}");
        }
    }

    #[test]
    fn accepts_the_canonical_counterparts() {
        let good: &[&str] = &[
            "0",
            "-1",
            "9223372036854775807",
            "-9223372036854775808",
            "{\"a\":1}",
            "{\"a\":\"A\"}",
            "{\"a\":\"é\"}",
            "{\"a\":\"/\"}",
            "{\"a\":\"\\u0001\"}",
            "[]",
            "{}",
        ];
        for case in good {
            assert!(is_canonical(case.as_bytes()), "must be accepted: {case:?}");
        }
    }

    #[test]
    fn out_of_range_and_too_deep_are_errors() {
        assert!(read_canonical(b"9223372036854775808").is_err());
        let at_limit = "[".repeat(MAX_DEPTH) + &"]".repeat(MAX_DEPTH);
        assert!(read_canonical(at_limit.as_bytes()).is_ok());
        assert!(
            to_value_bytes(&serde_json::from_str::<serde_json::Value>(&at_limit).unwrap()).is_ok()
        );
        let too_deep = "[".repeat(MAX_DEPTH + 1) + &"]".repeat(MAX_DEPTH + 1);
        assert!(read_canonical(too_deep.as_bytes()).is_err());
        assert!(
            to_value_bytes(&serde_json::from_str::<serde_json::Value>(&too_deep).unwrap()).is_err()
        );
    }

    #[test]
    fn key_order_is_unicode_scalar_order() {
        // Written order, and therefore the order the reader demands: "A" < "Z"
        // < "a" < "z" < "é" < U+1F600. Lone surrogates, the only case where a
        // UTF-16 code-unit sort could disagree, cannot be built in Rust.
        let value = json!({"😃": 1, "é": 2, "z": 3, "a": 4, "Z": 5, "A": 6});
        let bytes = to_value_bytes(&value).unwrap();
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            "{\"A\":6,\"Z\":5,\"a\":4,\"z\":3,\"é\":2,\"😃\":1}"
        );
        assert!(is_canonical(&bytes));
    }

    #[test]
    fn invalid_utf8_and_surrogate_bytes_are_refused() {
        assert!(!is_canonical(&[b'"', 0xff, b'"']));
        assert!(!is_canonical(&[b'"', 0xed, 0xa0, 0x80, b'"'])); // CESU-8 style lone surrogate
        assert!(!is_canonical(&[b'"', 0xc0, 0x80, b'"'])); // overlong NUL
    }

    #[test]
    fn typed_round_trip() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Example {
            b: i64,
            a: String,
        }
        let bytes = to_bytes(&Example {
            b: 2,
            a: "x".into(),
        })
        .unwrap();
        assert_eq!(bytes, br#"{"a":"x","b":2}"#);
        assert_eq!(
            from_bytes::<Example>(&bytes).unwrap(),
            Example {
                b: 2,
                a: "x".into()
            }
        );
    }

    #[test]
    fn size_limit_is_enforced() {
        let big = "x".repeat(MAX_ENCODED_BYTES + 1);
        assert!(to_value_bytes(&json!(big)).is_err());
        assert!(read_canonical(big.as_bytes()).is_err());
    }
}
