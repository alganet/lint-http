// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Retry-After` defects — a field sent where nothing says what it means.
//!
//! One entry, and it is the subject's whole content: the field's own section
//! defines it generally, with no condition on the status code, and then
//! elaborates two cases. Four contexts have a sentence about it — any `3xx`,
//! `503`, `413` and (outside RFC 9110) `429` — and on every other status a
//! recipient is simply not told what to do with the value.
//!
//! **What the field *says* is not here.** `Retry-After = HTTP-date /
//! delay-seconds` is `retry_after_date_or_delay`'s, and it owns the repeated
//! field line too; this subject reads presence and a status code and nothing
//! else.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field: who sends it, what it is for, and the two status contexts the
/// section elaborates without closing the set.
pub const RFC_9110_10_2_3: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("10.2.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3",
    note: "Defines Retry-After generally, with no condition on the status code, then says what it indicates on a 503 and on any 3xx",
};

defects! {
    /// A `Retry-After` on a status no document pairs it with.
    ///
    /// **`_redundant`, the ending that condemns nothing**, for the third time
    /// in this catalogue and on the same reading as
    /// [`location_redundant`](crate::violations::location::LOCATION_REDUNDANT)
    /// and `proxy_authenticate_redundant`: the field's own definition puts no
    /// condition on the status code, so nothing forbids this and `_forbidden`
    /// would invent a prohibition. What the finding says is that the value has
    /// nowhere to land — a client reading it here has been told to wait by a
    /// response that names nothing to retry.
    ///
    /// **The set of paired statuses is open and the entry says so.** § 10.2.3's
    /// two "When sent with" sentences elaborate cases rather than closing them,
    /// and § 15.5.14 shows a status definition naming the field on its own — so
    /// a future status may join the four without this entry changing.
    ///
    /// `info`, which is where `_redundant` starts and where nothing here argues
    /// for more.
    ///
    // cite(RFC 9110 § 10.2.3): "Servers send the "Retry-After" header field to indicate how long the user agent ought to wait before making a follow-up request."
    RETRY_AFTER_REDUNDANT = {
        id: "retry_after_redundant",
        title: "Retry-After is sent on a status no document pairs it with",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9110_10_2_3],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ending that condemns nothing, at the severity it starts from —
    /// there is no argument on this page for more, and the convention asks for
    /// one before an entry may take it.
    #[test]
    fn the_entry_condemns_nothing_and_is_ranked_accordingly() {
        assert!(RETRY_AFTER_REDUNDANT.id.ends_with("_redundant"));
        assert_eq!(RETRY_AFTER_REDUNDANT.default_severity, Severity::Info);
    }
}
