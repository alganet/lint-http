// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use std::num::ParseIntError;

/// Result of parsing a `Content-Range` header value.
#[derive(Debug, PartialEq, Eq)]
pub enum ContentRange {
    /// Example: `bytes 0-499/1234` or `bytes 0-499/*` (instance_length = None for `*`).
    Satisfied {
        first: u128,
        last: u128,
        instance_length: Option<u128>,
    },
    /// Example: `bytes */1234` used in `416 Range Not Satisfiable` responses.
    Unsatisfiable { instance_length: u128 },
}

/// Parse a `Content-Range` header value. Returns a `ContentRange` or an error string.
pub fn parse_content_range(s: &str) -> Result<ContentRange, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty header value".into());
    }

    // Expect unit SP range / instance-length
    let mut parts = s.splitn(2, ' ');
    let unit = parts.next().ok_or_else(|| "missing unit".to_string())?;
    if !unit.eq_ignore_ascii_case("bytes") {
        return Err(format!("unsupported unit '{}', expected 'bytes'", unit));
    }
    let rest = parts
        .next()
        .ok_or_else(|| "missing range/spec".to_string())?
        .trim();

    let slash_idx = rest
        .find('/')
        .ok_or_else(|| "missing '/' in range/spec".to_string())?;
    let left = rest[..slash_idx].trim();
    let right = rest[slash_idx + 1..].trim();

    if !left.is_empty() && left.starts_with('*') {
        // Left "*" should be exact
        if left != "*" {
            return Err("unexpected value before '/'".into());
        }
        // Right must be a number (instance-length)
        let instance_length =
            parse_u128(right).map_err(|e| format!("invalid instance-length: {}", e))?;
        return Ok(ContentRange::Unsatisfiable { instance_length });
    }

    // Otherwise expect first-last
    let dash_idx = left
        .find('-')
        .ok_or_else(|| "missing '-' in byte-range".to_string())?;
    let first = left[..dash_idx].trim();
    let last = left[dash_idx + 1..].trim();

    if first.is_empty() || last.is_empty() {
        return Err("missing first or last byte-pos".into());
    }

    let first_v = parse_u128(first).map_err(|e| format!("invalid first byte-pos: {}", e))?;
    let last_v = parse_u128(last).map_err(|e| format!("invalid last byte-pos: {}", e))?;
    if first_v > last_v {
        return Err("first byte-pos greater than last".into());
    }

    let instance_length = if right == "*" {
        None
    } else {
        Some(parse_u128(right).map_err(|e| format!("invalid instance-length: {}", e))?)
    };

    Ok(ContentRange::Satisfied {
        first: first_v,
        last: last_v,
        instance_length,
    })
}

fn parse_u128(s: &str) -> Result<u128, ParseIntError> {
    s.parse::<u128>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_satisfied() {
        let v = parse_content_range("bytes 0-499/1234").unwrap();
        assert_eq!(
            v,
            ContentRange::Satisfied {
                first: 0,
                last: 499,
                instance_length: Some(1234)
            }
        );

        let v2 = parse_content_range("bytes 5-5/*").unwrap();
        assert_eq!(
            v2,
            ContentRange::Satisfied {
                first: 5,
                last: 5,
                instance_length: None
            }
        );

        let v3 = parse_content_range("bytes  0-0 /  *").unwrap();
        assert_eq!(
            v3,
            ContentRange::Satisfied {
                first: 0,
                last: 0,
                instance_length: None
            }
        );
    }

    #[test]
    fn parse_valid_unsatisfiable() {
        let v = parse_content_range("bytes */1234").unwrap();
        assert_eq!(
            v,
            ContentRange::Unsatisfiable {
                instance_length: 1234
            }
        );
    }

    #[test]
    fn invalid_unit() {
        assert!(parse_content_range("items 0-1/3").is_err());
    }

    #[test]
    fn malformed_values() {
        assert!(parse_content_range("bytes 5-3/10").is_err());
        assert!(parse_content_range("bytes 5- /10").is_err());
        assert!(parse_content_range("bytes -5/10").is_err());
        assert!(parse_content_range("bytes */*").is_err());
        assert!(parse_content_range("bytes */x").is_err());
    }

    #[test]
    fn unexpected_star_prefix_reports_error() {
        let r = parse_content_range("bytes *1/1234");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("unexpected value"));
    }
}
