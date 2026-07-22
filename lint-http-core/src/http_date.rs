// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Parse and validate HTTP-date values.
//!
//! There are two obligations here and they are not the same one. A recipient must
//! accept all three formats; a sender must emit only IMF-fixdate. Reading a
//! timestamp is the recipient side: [`parse_http_date_to_datetime`] and
//! [`is_valid_http_date`]. Judging a timestamp somebody else generated is the
//! sender side: [`is_valid_imf_fixdate`]. A rule that asks "was this field
//! well-formed when it was sent" wants the second one, and saying `HTTP-date`
//! where it means `IMF-fixdate` is how a check ends up unable to fail.

use chrono::{DateTime, Utc};

/// Parse an HTTP-date string into a `chrono::DateTime<Utc>`.
///
/// Accepts all three formats — IMF-fixdate, RFC 850, and asctime — which is what
/// a recipient is required to do. Returns an `anyhow::Error` when parsing fails.
pub fn parse_http_date_to_datetime(s: &str) -> anyhow::Result<DateTime<Utc>> {
    // The delegation is the claim: `httpdate` tries IMF-fixdate, then RFC 850,
    // then asctime, which is exactly the required set.
    // cite(RFC 9110 § 5.6.7): "HTTP-date = IMF-fixdate / obs-date"
    // cite(RFC 9110 § 5.6.7): "A recipient that parses a timestamp value in an HTTP field MUST accept all three HTTP-date formats."
    let st =
        httpdate::parse_http_date(s).map_err(|e| anyhow::anyhow!("httpdate parse error: {}", e))?;
    Ok(DateTime::<Utc>::from(st))
}

/// Return true when the string is a valid HTTP-date — any of the three formats.
///
/// This is the recipient's question. To ask whether a *sender* was allowed to emit
/// it, use [`is_valid_imf_fixdate`].
pub fn is_valid_http_date(s: &str) -> bool {
    parse_http_date_to_datetime(s).is_ok()
}

/// Return true when the string is specifically an IMF-fixdate — the only format a
/// sender is permitted to generate.
///
/// IMF-fixdate is fixed-length, fixed-zone and fixed-capitalization, so it is the
/// one format that survives a parse/format round trip unchanged. The two obsolete
/// formats parse, then re-serialize into IMF-fixdate and no longer match, which is
/// precisely the distinction being drawn.
pub fn is_valid_imf_fixdate(s: &str) -> bool {
    // cite(RFC 9110 § 5.6.7): "When a sender generates a field that contains one or more timestamps defined as HTTP-date, the sender MUST generate those timestamps in the IMF-fixdate format."
    let t = s.trim();
    match httpdate::parse_http_date(t) {
        Ok(st) => httpdate::fmt_http_date(st) == t,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn parses_valid_http_date() -> anyhow::Result<()> {
        let s = "Wed, 21 Oct 2015 07:28:00 GMT";
        let dt = parse_http_date_to_datetime(s)?;
        assert_eq!(dt.year(), 2015);
        assert_eq!(dt.month(), 10);
        assert_eq!(dt.day(), 21);
        Ok(())
    }

    #[test]
    fn imf_fixdate_is_the_only_format_a_sender_may_generate() {
        // The three formats RFC 9110 5.6.7 names, by its own examples.
        let imf = "Sun, 06 Nov 1994 08:49:37 GMT";
        let rfc850 = "Sunday, 06-Nov-94 08:49:37 GMT";
        let asctime = "Sun Nov  6 08:49:37 1994";

        // A recipient must accept all three.
        assert!(is_valid_http_date(imf));
        assert!(is_valid_http_date(rfc850));
        assert!(is_valid_http_date(asctime));

        // A sender may only generate the first.
        assert!(is_valid_imf_fixdate(imf));
        assert!(!is_valid_imf_fixdate(rfc850));
        assert!(!is_valid_imf_fixdate(asctime));

        assert!(!is_valid_imf_fixdate("not-a-date"));
    }

    #[test]
    fn invalid_date_returns_error() {
        let s = "not-a-date";
        assert!(parse_http_date_to_datetime(s).is_err());
        assert!(!is_valid_http_date(s));
    }
}
