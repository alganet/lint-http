// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Small helpers to parse and validate HTTP-date (IMF-fixdate) values.

use chrono::{DateTime, Utc};

/// Parse an HTTP-date string (IMF-fixdate) into a `chrono::DateTime<Utc>`.
/// Returns an `anyhow::Error` when parsing fails.
pub fn parse_http_date_to_datetime(s: &str) -> anyhow::Result<DateTime<Utc>> {
    let st =
        httpdate::parse_http_date(s).map_err(|e| anyhow::anyhow!("httpdate parse error: {}", e))?;
    Ok(DateTime::<Utc>::from(st))
}

/// Return true when the string is a valid HTTP-date (IMF-fixdate).
pub fn is_valid_http_date(s: &str) -> bool {
    parse_http_date_to_datetime(s).is_ok()
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
    fn invalid_date_returns_error() {
        let s = "not-a-date";
        assert!(parse_http_date_to_datetime(s).is_err());
        assert!(!is_valid_http_date(s));
    }
}
