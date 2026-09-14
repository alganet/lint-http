// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Access-Control-Allow-Origin` defects — a field whose whole value is one of
//! three alternatives, and the two ways a sender writes something else.
//!
//! § 3.3.3 says what may be on the line: the literal value of the `Origin`
//! request header, which may be `null`, or `*`. Nothing else derives from it —
//! there is no list form, no wildcard host, no case folding of `null` — and the
//! CORS check compares the whole field value byte for byte, so a value that is
//! none of the three shares the response with nobody.
//!
//! **Two entries, and the split is between writing no value and writing the
//! wrong one.** That is the same line
//! [`origin_agent_cluster`](crate::violations::origin_agent_cluster) drew, for
//! the same reason: a server that emitted an empty line meant to state
//! something and emitted nothing — a template that expanded to nothing, a proxy
//! that dropped a value and kept the line — while a server that wrote
//! `example.com` stated something and got it wrong.
//!
//! **What is deliberately *not* split is the comma from the bad origin.** The
//! reader asks two questions — is there exactly one member, and is that member
//! an origin — but the field has no list form for a comma to break, so
//! `https://a, https://b` is not a list defect: it is a value deriving from
//! none of the three alternatives, exactly as `example.com` is. One sentence
//! refuses both, the repair is to write one of the three either way, and the
//! message carries which shape arrived.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The response header, and the three alternatives its value may be.
pub const FETCH_3_3_3: SpecRef = SpecRef {
    spec: "Fetch",
    section: Some("3.3.3"),
    url: "https://fetch.spec.whatwg.org/#http-access-control-allow-origin",
    note: "`Access-Control-Allow-Origin` carries one value: an echoed origin, `null`, or `*`",
};

defects! {
    /// The header is written and no value is written on it: an empty line, or
    /// one made of nothing but the commas of a list that is not there.
    ///
    /// Separated from the value that is merely not one of the three because the
    /// senders differ and so does the fix. An `example.com` is a server that
    /// stated an origin and mis-stated it; an empty value is a server that
    /// meant to state one and emitted nothing.
    ///
    // cite(Fetch § 3.3.3): "Indicates whether the response can be shared, via returning the literal value of the `Origin` request header (which can be `null`) or `*` in a response."
    ACCESS_CONTROL_ALLOW_ORIGIN_EMPTY = {
        id: "access_control_allow_origin_empty",
        title: "Access-Control-Allow-Origin is written with no value on it",
        message: "Access-Control-Allow-Origin is written with no value",
        default_severity: Severity::Warn,
        spec: &[FETCH_3_3_3],
    }

    /// A value on the line, and it derives from none of the three alternatives:
    /// more than one comma-separated member, a host with no scheme, an
    /// authority with a path after it, an uppercase `NULL` — the literal is
    /// case-sensitive — or an octet outside visible US-ASCII, which is inside
    /// none of them either.
    ///
    /// **One entry for both of the reader's questions.** It asks whether there
    /// is exactly one member and then whether that member is an origin, but the
    /// field has no list form: a comma does not break a construct here, it
    /// produces a value the CORS check's byte comparison matches against no
    /// origin at all — which is precisely what `example.com` produces. Same
    /// sentence, same repair, one id, and the message names the shape.
    ///
    // cite(Fetch § 3.3.3): "Indicates whether the response can be shared, via returning the literal value of the `Origin` request header (which can be `null`) or `*` in a response."
    ACCESS_CONTROL_ALLOW_ORIGIN_MALFORMED = {
        id: "access_control_allow_origin_malformed",
        title: "Access-Control-Allow-Origin states a value that is none of `*`, `null` and a serialized origin",
        message: "",
        default_severity: Severity::Warn,
        spec: &[FETCH_3_3_3],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Nothing to rank. Both entries leave the response shared with nobody —
    /// the CORS check compares the whole field value, and neither an empty line
    /// nor a mis-stated origin matches one — so the two sit at the same
    /// severity rather than being differentiated to look converted.
    #[test]
    fn neither_value_shares_the_response_so_neither_outranks_the_other() {
        assert_eq!(
            ACCESS_CONTROL_ALLOW_ORIGIN_EMPTY.default_severity,
            ACCESS_CONTROL_ALLOW_ORIGIN_MALFORMED.default_severity,
        );
    }

    /// The entry that names a value leaves its message to the site, because the
    /// operator's next question is which value arrived; the entry for a line
    /// with nothing on it has nothing to name.
    #[test]
    fn only_the_entry_naming_a_value_leaves_its_message_to_the_site() {
        assert!(!ACCESS_CONTROL_ALLOW_ORIGIN_EMPTY.message.is_empty());
        assert!(ACCESS_CONTROL_ALLOW_ORIGIN_MALFORMED.message.is_empty());
    }
}
