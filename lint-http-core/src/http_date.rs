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
///
/// **Nothing is trimmed here and nothing needs to be**, which is worth stating
/// because the reverse was assumed for long enough to be written down. The
/// dependency's own `FromStr` opens `if !s.is_ascii() { return Err(..) }` and then
/// `s.trim()`, so a padded value parses and a value carrying any octet at or above
/// %x80 is refused before the trim can touch it. A caller adding a trim in front
/// of this is either duplicating the second step or defeating the first.
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
///
/// **This measures the string it is given, and the whitespace question is the
/// caller's.** It used to open `let t = s.trim()` and then round-trip against `t`,
/// which had no sentence behind it and one against it. The production prints its
/// own whitespace as `SP` at fixed offsets, and § 5.6.7 states the rest as a MUST
/// NOT on the party every caller of this function is blaming. Where a *field
/// value* carries leading or trailing `OWS`, that whitespace is outside the value
/// by § 5.5 and outside the date by RFC 9112 § 5's `field-line` — a fact about the
/// field line, which is the caller's to know and not this function's to assume.
/// Each caller now excludes `OWS` itself, and says which sentence puts it there.
///
/// The round trip is also why the trim was not a harmless duplicate of the one
/// `httpdate::parse_http_date` performs internally: the comparison ran against the
/// *trimmed* string, so `"Sun, 06 Nov 1994 08:49:37 GMT<%xA0>"` had its %xA0
/// removed here, then reached a parser that refuses a non-ASCII string outright
/// and never saw one — and the function answered `true` for a value no
/// `IMF-fixdate` derives. Handing the whole string over lets that guard do its job.
///
/// **No caller in this workspace could reach that answer, and saying so is the
/// point.** Four of the five read their value through `HeaderValue::to_str`, which
/// admits no octet at or above %x80 at all; the fifth reads a `warn-date` one
/// `char` per octet and its own rule refuses a padded one two branches earlier. So
/// this was a wrong answer with no reachable question — until a caller arrives that
/// does not have either guard, which is what a `pub` function in a crate the proxy
/// re-exports has to be written for.
///
/// cite(RFC 9110 § 5.6.7): "IMF-fixdate  = day-name "," SP date1 SP time-of-day SP GMT"
/// cite(RFC 9110 § 5.6.7): "A sender MUST NOT generate additional whitespace in an HTTP-date beyond that specifically included as SP in the grammar"
pub fn is_valid_imf_fixdate(s: &str) -> bool {
    // cite(RFC 9110 § 5.6.7): "When a sender generates a field that contains one or more timestamps defined as HTTP-date, the sender MUST generate those timestamps in the IMF-fixdate format."
    match httpdate::parse_http_date(s) {
        Ok(st) => httpdate::fmt_http_date(st) == s,
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

    /// The sender-side verdict measures the whole string. `IMF-fixdate` prints
    /// its own whitespace as `SP` at fixed offsets and § 5.6.7 forbids a sender
    /// any more of it, so a padded value is not one — whatever the padding is,
    /// and whether or not the field line it came from was allowed to carry
    /// `OWS`. Excluding that `OWS` is the caller's, because only the caller knows
    /// it was a field value.
    #[test]
    fn a_padded_date_is_not_an_imf_fixdate() {
        let imf = "Sun, 06 Nov 1994 08:49:37 GMT";
        assert!(is_valid_imf_fixdate(imf));

        for padded in [
            format!(" {imf}"),
            format!("{imf} "),
            format!("\t{imf}"),
            format!("{imf}\t"),
        ] {
            assert!(
                !is_valid_imf_fixdate(&padded),
                "{padded:?} was accepted as an IMF-fixdate"
            );
        }
    }

    /// The %xA0 case is the one the removed trim answered backwards. Read one
    /// `char` per octet, the padding is U+00A0 — `obs-text`, and `str::trim`
    /// removes it. Doing so *here* handed the dependency a string that had become
    /// pure ASCII, so its own `is_ascii` refusal never fired and the function
    /// returned `true` for a value no date production writes.
    #[test]
    fn an_obs_text_padded_date_is_not_an_imf_fixdate() {
        let padded: String = b"Sun, 06 Nov 1994 08:49:37 GMT\xA0"
            .iter()
            .map(|&b| b as char)
            .collect();
        assert!(!is_valid_imf_fixdate(&padded));
        assert!(!is_valid_http_date(&padded));

        // What the old body did to it, spelled out: the trim made it a date.
        assert!(is_valid_imf_fixdate(padded.trim()));
    }

    /// The dependency's two behaviours this module rests on, pinned in the crate
    /// that owns the call. `httpdate::parse_http_date` goes through `FromStr`,
    /// which refuses a non-ASCII string *before* trimming and then applies
    /// `str::trim` itself — so the recipient's reader needs no trim of its own,
    /// and adding one in front of it would defeat the refusal.
    #[test]
    fn httpdate_refuses_non_ascii_and_trims_ascii_whitespace_itself() {
        let imf = "Sun, 06 Nov 1994 08:49:37 GMT";
        assert!(httpdate::parse_http_date(&format!("  {imf}  ")).is_ok());

        let non_ascii: String = b"Sun, 06 Nov 1994 08:49:37 GMT\xA0"
            .iter()
            .map(|&b| b as char)
            .collect();
        assert!(httpdate::parse_http_date(&non_ascii).is_err());
    }
}
