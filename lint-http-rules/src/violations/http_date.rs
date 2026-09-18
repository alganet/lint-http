// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `HTTP-date` defects — the timestamp production every dated field carries.
//!
//! `Last-Modified`, `If-Modified-Since`, `If-Unmodified-Since`, `Date`,
//! `Expires`, `Retry-After`, `Sunset`, `Deprecation`, a `Warning`'s
//! `warn-date`, a cookie's `Expires` attribute: eighteen rules in this tree
//! reach [`crate::http_date`], and each of them used to word the same two
//! verdicts about its own field. One production, one pair of ids.
//!
//! **The two entries are what a `bool` could not separate.** § 5.6.7 states two
//! obligations that run in opposite directions — a recipient MUST accept all
//! three formats, a sender MUST generate only IMF-fixdate — so a value can fail
//! the sender's requirement while satisfying the recipient's completely.
//! `is_valid_imf_fixdate` answered both with one `false`, which is why the
//! reader was typed before this subject could be written: sort at the mapping
//! fn, never widen the reader, and where the reader is a `bool` there is
//! nothing to sort.
//!
//! **The obsolete format defaults below the other two, and the ranking is about
//! the recipient rather than about the requirement.** All three sentences are
//! MUSTs and the sender broke one of them either way; what differs is what a
//! conformant recipient does. `Sunday, 06-Nov-94 08:49:37 GMT` names an instant
//! every recipient is *required* to read, so the field works and the spelling
//! is retired. `not-a-date` names no instant at all, and a padded IMF-fixdate
//! derives from a production that prints no whitespace — both are values a
//! strict recipient refuses. So: **a value the specification obliges the other
//! party to accept sits below one it does not** — the ranking rule of thumb
//! this catalogue uses, read through the recipient rather than through the
//! sentence.

use crate::http_date::HttpDateDefect;
use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::{defects, ViolationDef};

/// The production, both obligations, and the two obsolete formats — § 5.6.7 is
/// where the whole of `HTTP-date` is written.
pub const RFC_9110_5_6_7: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.7"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7",
    note: "Date/Time Formats — `HTTP-date = IMF-fixdate / obs-date`, the recipient's MUST to accept all three, and the sender's MUST to generate only the first",
};

/// Where § 5.6.7 sends a reader for what `day-name` and the rest of the
/// elements *mean*, as opposed to what they may be spelled as.
pub const RFC_5322_3_3: SpecRef = SpecRef {
    spec: "RFC 5322",
    section: Some("3.3"),
    url: "https://www.rfc-editor.org/rfc/rfc5322.html#section-3.3",
    note: "Date and Time Specification — the semantics § 5.6.7 borrows, including the requirement that a date-time be semantically valid",
};

defects! {
    /// A timestamp none of the three formats parses. The field names no
    /// instant, so everything downstream of it — a cache's freshness
    /// arithmetic, a conditional request's comparison — has nothing to work
    /// from.
    ///
    // cite(RFC 9110 § 5.6.7): "HTTP-date = IMF-fixdate / obs-date"
    HTTP_DATE_MALFORMED = {
        id: "http_date_malformed",
        title: "Timestamp derives from no HTTP-date format",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_5_6_7],
        strength: Strength::Grammar,
    }

    /// A date-valued field written with nothing on it, or with nothing but
    /// `OWS`.
    ///
    /// **Distinct from [`HTTP_DATE_MALFORMED`] beside it, and the sender is
    /// why.** A value that does not derive from any of the three date formats
    /// is a sender that wrote a timestamp and got it wrong; an empty one is a
    /// sender that meant to write one and emitted nothing — a template that
    /// expanded to nothing, a proxy that dropped a value and kept the line. The
    /// closed vocabulary separates the two everywhere and the evidence supports
    /// it here: both are in the capture.
    ///
    /// **`OWS` and not `str::trim`** is what "nothing but whitespace" means: an
    /// `obs-text` octet is not whitespace of any kind, and trimming it would
    /// call a value that holds one empty.
    ///
    /// `error`, with the rest of the subject: `HTTP-date` generates neither
    /// alternative from nothing. The field states no time and a recipient's
    /// answer is to act as though it were not there, which is the cost.
    ///
    // cite(RFC 9110 § 5.6.7): "HTTP-date = IMF-fixdate / obs-date"
    HTTP_DATE_EMPTY = {
        id: "http_date_empty",
        title: "A date field is written with no timestamp on it",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_5_6_7],
        strength: Strength::Grammar,
    }

    /// A timestamp written in RFC 850's or asctime's format. Both parse, both
    /// name the instant they mean, and a recipient is required to read them.
    ///
    /// **So this is the sender's requirement alone, and `error` is what that
    /// means** — § 5.6.7 tells a sender which format to generate, in as many
    /// words. It used to be `info`, on the argument that the message works and
    /// only the spelling is retired; the message working is what a reader
    /// deserves to know and not what ranks the finding.
    ///
    /// The `_obsolete` ending's second use, and the first under a MUST NOT
    /// rather than under a superseded recommendation: `cookie_domain_leading_
    /// dot_obsolete` is a form a later document stopped defining, this is one a
    /// later document still defines *for recipients* and refuses to senders.
    ///
    // cite(RFC 9110 § 5.6.7): "When a sender generates a field that contains one or more timestamps defined as HTTP-date, the sender MUST generate those timestamps in the IMF-fixdate format."
    HTTP_DATE_OBSOLETE = {
        id: "http_date_obsolete",
        title: "Timestamp is written in an obsolete date format",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_5_6_7],
        strength: Strength::Must,
    }

    /// An IMF-fixdate with whitespace around it, inside the value. The
    /// production prints `SP` at three fixed offsets and § 5.6.7 refuses a
    /// sender any more, so the padding derives from nothing — and unlike the
    /// obsolete spellings, no sentence requires a recipient to read past it.
    /// That is why it defaults *above* the obsolete format and beside the
    /// unreadable one: a strict recipient refuses it, where every recipient is
    /// obliged to accept an RFC 850 date.
    ///
    /// Not the `_whitespace_or_control_forbidden` half of the pair
    /// `docs/development.md` mandates: the octet is not inside a value whose
    /// alphabet excludes it but around a construct that is otherwise exactly
    /// what was asked for, which is the same distinction
    /// `parameter_equals_whitespace_forbidden` draws.
    ///
    /// Where the timestamp came off a field line, the `OWS` beside it is
    /// outside the value by § 5.5 and the reading rule excludes it before
    /// measuring — so this reports the padding a *quoted* timestamp carries,
    /// like a `Warning`'s `warn-date`.
    ///
    // cite(RFC 9110 § 5.6.7): "A sender MUST NOT generate additional whitespace in an HTTP-date beyond that specifically included as SP in the grammar"
    HTTP_DATE_WHITESPACE_FORBIDDEN = {
        id: "http_date_whitespace_forbidden",
        title: "Timestamp is padded with whitespace the grammar does not print",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_5_6_7],
        strength: Strength::Must,
    }

    /// A timestamp naming a weekday its own date does not fall on:
    /// `Fri, 01 Jan 1980 00:00:00 GMT`, where the first of January 1980 was a
    /// Tuesday. Both halves are written in the spelling § 5.6.7 fixes and they
    /// disagree with each other.
    ///
    /// **Distinct from [`HTTP_DATE_MALFORMED`] above, and the production is
    /// why.** `IMF-fixdate` puts `day-name` and `date1` side by side and ties
    /// them to nothing, so this value derives from the grammar exactly as
    /// written and names one instant, unambiguously, without the weekday. The
    /// entry above says the field names no instant and everything downstream
    /// of it has nothing to work from; said here that would be false, and it
    /// was said here — every dated field reported this as the value no format
    /// parses, because the reading came from whether a strict parser would
    /// accept the string rather than from what was wrong with it.
    ///
    /// **What the value does break is § 5.6.7's other sentence about
    /// `day-name`.** The grammar is not the whole of the section: it hands the
    /// *semantics* of `day-name`, `day`, `month`, `year` and `time-of-day` to
    /// RFC 5322 § 3.3, where a date-time MUST be semantically valid and the
    /// day-of-week MUST be the day the date implies. So the sender broke a
    /// `MUST` and `error` is what that means — the same level the unreadable
    /// value carries, which is the point: what changes is the claim, not the
    /// rank.
    ///
    /// The cost is real and small. § 5.6.7 encourages a recipient to be robust
    /// in parsing timestamps, so most read the date and drop the weekday; a
    /// strict one refuses the value outright, and the two populations disagree
    /// about a response nobody meant to write ambiguously.
    ///
    // cite(RFC 9110 § 5.6.7): "The semantics of day-name, day, month, year, and time-of-day are the same as those defined for the Internet Message Format constructs with the corresponding name ([RFC5322], Section 3.3)."
    // cite(RFC 5322 § 3.3): "A date-time specification MUST be semantically valid.  That is, the day-of-week (if included) MUST be the day implied by the date"
    HTTP_DATE_DAY_NAME_CONFLICTING = {
        id: "http_date_day_name_conflicting",
        title: "Timestamp names a weekday its own date does not fall on",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_9110_5_6_7, RFC_5322_3_3],
        strength: Strength::Must,
    }
}

/// The defect a [`HttpDateDefect`] reports as.
pub fn http_date_defect(defect: HttpDateDefect) -> &'static ViolationDef {
    match defect {
        HttpDateDefect::Unparsable => &HTTP_DATE_MALFORMED,
        HttpDateDefect::ObsoleteFormat => &HTTP_DATE_OBSOLETE,
        HttpDateDefect::SurroundingWhitespace => &HTTP_DATE_WHITESPACE_FORBIDDEN,
        HttpDateDefect::DayNameConflicting => &HTTP_DATE_DAY_NAME_CONFLICTING,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_date::check_imf_fixdate;

    /// The mapping, and the two values that reach each entry. Written against
    /// the reader rather than against the variants, because the whole point of
    /// typing it was that a `bool` sent both of these to one id.
    #[test]
    fn the_obsolete_spellings_and_the_unreadable_value_are_two_ids() {
        for value in ["Sunday, 06-Nov-94 08:49:37 GMT", "Sun Nov  6 08:49:37 1994"] {
            let defect = check_imf_fixdate(value).expect_err("a sender may generate neither");
            assert_eq!(http_date_defect(defect).id, "http_date_obsolete", "{value}");
        }
        let defect = check_imf_fixdate("not-a-date").expect_err("no format parses it");
        assert_eq!(http_date_defect(defect).id, "http_date_malformed");
        assert!(check_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT").is_ok());

        // The trap the round trip alone walks into: this *is* the format
        // § 5.6.7 asks for, with octets around it that the production never
        // prints. Calling it obsolete would report RFC 850 at a value written
        // in neither obsolete format.
        for padded in [
            " Sun, 06 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 08:49:37 GMT ",
        ] {
            let defect = check_imf_fixdate(padded).expect_err("the production prints no OWS");
            assert_eq!(
                http_date_defect(defect).id,
                "http_date_whitespace_forbidden",
                "{padded:?}",
            );
        }

        // Everything else a sender might spell differently is refused by the
        // parser outright, so it arrives as the unreadable value it is.
        for refused in [
            "sun, 06 nov 1994 08:49:37 gmt",
            "Sun,  06 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 08:49:37 UTC",
        ] {
            let defect = check_imf_fixdate(refused).expect_err("no format parses it");
            assert_eq!(
                http_date_defect(defect).id,
                "http_date_malformed",
                "{refused}"
            );
        }
    }

    /// **This test used to assert the opposite, and its old comment said why in
    /// as many words: "the ranking is by what a conformant recipient does with
    /// the value, not by the strength of the sentence the sender broke."**
    /// That is the doctrine the catalogue no longer holds.
    ///
    /// § 5.6.7 addresses the sender three times and this subject is all three:
    /// generate IMF-fixdate, generate no extra whitespace, and generate
    /// something the production admits. A recipient is separately required to
    /// read the obsolete formats, which is why the message still works — and
    /// working is not the question the level answers.
    #[test]
    fn the_three_ways_to_write_the_timestamp_wrongly_rank_together() {
        for def in [
            &HTTP_DATE_OBSOLETE,
            &HTTP_DATE_MALFORMED,
            &HTTP_DATE_WHITESPACE_FORBIDDEN,
        ] {
            assert_eq!(def.default_severity, Severity::Error, "{}", def.id);
        }
    }
}
