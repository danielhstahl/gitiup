//! The few codecs the API needs, without a dependency for each of them.
//!
//! Base64 (because the git-data endpoints speak it), percent-encoding (because a
//! ref name contains `/` and a query string cares), and the canonical JSON the
//! rest of the workspace already agrees on. Hand-rolling these is a deliberate
//! trade: ~100 lines reviewed once, instead of a dependency tree that a
//! supply-chain ticket then has to pin and an auditor has to trust.

/// The base64 alphabet, standard (not URL-safe): the API sends standard base64 and
/// pads it.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes as standard padded base64, in `line_length`-column lines when
/// `line_length` is `Some` (the API accepts — and for large blobs sends — wrapped
/// base64, so decoding must ignore whitespace either way).
pub fn encode_base64(bytes: &[u8]) -> String {
    encode_base64_wrapped(bytes, None)
}

/// [`encode_base64`] with an optional line wrap.
pub fn encode_base64_wrapped(bytes: &[u8], line_length: Option<usize>) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4 + 8);
    let mut column = 0usize;
    for chunk in bytes.chunks(3) {
        let mut buffer = [0u8; 3];
        buffer[..chunk.len()].copy_from_slice(chunk);
        let words = [
            buffer[0] >> 2,
            ((buffer[0] & 0b0000_0011) << 4) | (buffer[1] >> 4),
            ((buffer[1] & 0b0000_1111) << 2) | (buffer[2] >> 6),
            buffer[2] & 0b0011_1111,
        ];
        // Three input bytes make four characters; two inputs make three and a
        // pad, one makes two and two pads.
        let significant = chunk.len() + 1;
        for (index, word) in words.iter().enumerate() {
            if index < significant {
                out.push(ALPHABET[*word as usize] as char);
            } else {
                out.push('=');
            }
            column += 1;
            if line_length.is_some_and(|width| column == width) {
                out.push('\n');
                column = 0;
            }
        }
    }
    out
}

/// Decode standard base64, ignoring whitespace (the API wraps long values).
///
/// Groups of four, always, and a trailing group of one character is refused: it
/// cannot be a real encoding, and "decode what you can" is how a truncated blob
/// becomes a corrupt one that still hashes-checks-out nowhere.
///
/// The error is a plain string because it always becomes part of a
/// [`gitiup_host::HostError::Invalid`] about a specific stored object, where the
/// caller already knows what was being decoded.
pub fn decode_base64(text: &str) -> Result<Vec<u8>, String> {
    let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let padding = clean.chars().rev().take_while(|c| *c == '=').count();
    if padding > 2 {
        return Err("base64 has more than two padding characters".to_string());
    }
    let body = &clean[..clean.len().saturating_sub(padding)];
    if body.chars().any(|c| c == '=') {
        return Err("base64 has data after its padding".to_string());
    }
    let mut out = Vec::with_capacity((body.len() / 4) * 3 + 3);
    let groups = body.as_bytes().chunks(4);
    let mut offset = 0usize;
    for group in groups {
        let mut accumulator: u32 = 0;
        for byte in group {
            let value = ALPHABET
                .iter()
                .position(|slot| *slot == *byte)
                .ok_or_else(|| format!("'{}' is not in the base64 alphabet", *byte as char))?;
            accumulator = (accumulator << 6) | value as u32;
        }
        let emitted = match group.len() {
            1 => return Err("base64 ends in a single leftover character".to_string()),
            2 => 1,
            3 => 2,
            _ => 3,
        };
        // The group holds `group.len() * 6` bits and describes `emitted` bytes;
        // the rest is the next group's business.
        let shift = group.len() * 6 - emitted * 8;
        let value = accumulator >> shift;
        let bytes = value.to_be_bytes();
        out.extend_from_slice(&bytes[4 - emitted..]);
        offset += group.len();
    }
    let _ = offset;
    Ok(out)
}

/// Percent-encode a single path segment, so a ref name (`refs/heads/main`) can be
/// a path *segment* rather than a path.
///
/// GitHub accepts a ref name with its slashes in the path (`/git/ref/refs/heads/x`)
/// but encoding the slashes is what keeps a proxy, a recorder and a log line all
/// agreeing about where the request went. Unreserved characters per RFC 3986 are
/// left alone.
pub fn percent_encode(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Percent-encode a query *value* (spaces and `+` included).
pub fn percent_encode_query(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push_str("%20"),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Build a query string from ordered key/value pairs.
pub fn query(pairs: &[(&str, String)]) -> String {
    let rendered: Vec<String> = pairs
        .iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(key, value)| format!("{key}={}", percent_encode_query(value)))
        .collect();
    if rendered.is_empty() {
        String::new()
    } else {
        format!("?{}", rendered.join("&"))
    }
}

/// Canonical JSON, the same bytes [`gitiup_host::config::canonical_json`] produces
/// — a recorded fixture and a live call must not differ by key order.
pub fn canonical_json(value: &serde_json::Value) -> Result<Vec<u8>, gitiup_host::HostError> {
    gitiup_host::config::canonical_json(value)
}

/// Split a URL into `(origin, path_with_query)`.
pub fn split_url(url: &str) -> Option<(&str, &str)> {
    let scheme_end = url.find("://")?;
    let rest = &url[scheme_end + 3..];
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let origin = &url[..scheme_end + 3 + authority_end];
    let tail = &rest[authority_end..];
    Some((origin, if tail.is_empty() { "/" } else { tail }))
}

/// The host part of a URL, without userinfo or port.
pub fn url_host(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return String::new();
    };
    let rest = &url[scheme_end + 3..];
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    authority
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// Whether a host is loopback, so plain `http://` is allowed for a local test
/// server and nowhere else.
pub fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']);
    host == "localhost" || host.ends_with(".localhost") || host.starts_with("127.") || host == "::1"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_known_vectors() {
        for (text, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode_base64(text.as_bytes()), expected, "{text}");
            assert_eq!(
                decode_base64(expected).unwrap(),
                text.as_bytes(),
                "{expected}"
            );
        }
    }

    #[test]
    fn base64_survives_every_byte_and_wrapping() {
        let bytes: Vec<u8> = (0u16..=255).map(|b| b as u8).cycle().take(1000).collect();
        let encoded = encode_base64_wrapped(&bytes, Some(76));
        assert!(encoded.contains('\n'), "wrapped output must be wrapped");
        assert_eq!(decode_base64(&encoded).unwrap(), bytes);
        assert_eq!(decode_base64(&encode_base64(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn base64_rejects_junk_rather_than_guessing() {
        assert!(decode_base64("Zm9v*").is_err());
        assert!(
            decode_base64("Zm9vZ").is_err(),
            "a trailing single character is not a group"
        );
        assert!(
            decode_base64("Zm9v=g").is_err(),
            "data after padding is refused"
        );
    }

    #[test]
    fn ref_names_encode_into_one_path_segment() {
        assert_eq!(percent_encode("refs/heads/main"), "refs%2Fheads%2Fmain");
        assert_eq!(
            split_url("https://api.github.com/repos/o/r?per_page=1"),
            Some(("https://api.github.com", "/repos/o/r?per_page=1"))
        );
        assert_eq!(
            url_host("https://ghe.example.com/api/v3/x"),
            "ghe.example.com"
        );
        assert_eq!(
            query(&[("state", "all".into()), ("per_page", "100".into())]),
            "?state=all&per_page=100"
        );
        assert_eq!(query(&[("empty", String::new())]), "");
    }

    #[test]
    fn loopback_is_the_only_plain_http_we_accept() {
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("localhost"));
        assert!(!is_loopback_host("api.github.com"));
    }
}
