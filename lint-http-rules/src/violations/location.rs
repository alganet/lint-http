// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Location` defects — a status that asked for the field, and a status the
//! field means nothing on.
//!
//! Two entries, read by two rules from the two sides of one pairing: the field
//! is absent where a status's own definition asks for it, and present where no
//! definition gives it a referent. What the *value* is belongs to
//! [`uri`](crate::violations::uri), which
//! `location_header_uri_valid` declares; neither entry here reads a value at
//! all.
//!
//! **The two rank differently and the documents are why.** Five statuses ask
//! for the field — four with a SHOULD and `303` by being defined in terms of it
//! — so a redirect with no `Location` leaves a user agent with nowhere to go,
//! and that is `warn`. Nothing forbids the field anywhere else, so the other
//! entry is `_redundant` at `info`, beside
//! [`proxy_authenticate_redundant`](crate::violations::proxy_authenticate) and
//! for the same reason: the header was avoidable, not wrong.
//!
//! **The absence entry names five sections and is cited on none of them**, which
//! is the shape 2.126 settled. Which sentence governs depends on the status in
//! front of the rule, so choosing one here would put a `301` reference on a
//! `307` finding; the message names the section it was read from, exactly as it
//! did while the finding carried no reference at all.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field itself: its grammar, and the two kinds of response its value has a
/// defined referent on.
pub const RFC_9110_10_2_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("10.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2",
    note: "`Location = URI-reference`; the value's referent is defined for 201 (Created) and for 3xx (Redirection) responses, and for no other status",
};

/// 301 Moved Permanently.
pub const RFC_9110_15_4_2: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("15.4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.2",
    note: "301 Moved Permanently: the server SHOULD generate a Location header field containing a preferred URI reference for the new permanent URI",
};

/// 302 Found.
pub const RFC_9110_15_4_3: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("15.4.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.3",
    note: "302 Found: the server SHOULD generate a Location header field containing a URI reference for the different URI",
};

/// 303 See Other — the status defined in terms of the field.
pub const RFC_9110_15_4_4: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("15.4.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.4",
    note: "303 See Other: the status is defined as a redirection to the resource indicated by a URI in the Location header field",
};

/// 307 Temporary Redirect.
pub const RFC_9110_15_4_8: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("15.4.8"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.8",
    note: "307 Temporary Redirect: the server SHOULD generate a Location header field containing a URI reference for the different URI",
};

/// 308 Permanent Redirect.
pub const RFC_9110_15_4_9: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("15.4.9"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.9",
    note: "308 Permanent Redirect: the server SHOULD generate a Location header field containing a preferred URI reference for the new permanent URI",
};

defects! {
    /// A response on a status whose own definition asks for `Location`, with no
    /// such field line on it.
    ///
    /// **Five sentences, one entry, and no citation on the finding.** Each of
    /// the five statuses states the requirement in its own section — four as a
    /// SHOULD, and `303` by defining the status as a redirection to the
    /// resource the field names — so no one of them governs a finding about
    /// another, and the message names the section it was read from. Splitting
    /// per status would be five ids for one defect with one repair.
    ///
    /// **`300` and `201` are not this entry.** § 15.4.1's SHOULD is conditioned
    /// on the server *having* a preferred choice, which nothing on the wire
    /// records; § 15.3.2 describes a `201` without the field rather than asking
    /// for one, and the sentence that does ask is about `POST`.
    ///
    /// `warn`: a user agent that would have followed the redirect has no target.
    ///
    // cite(RFC 9110 § 15.4.4): "The 303 (See Other) status code indicates that the server is redirecting the user agent to a different resource, as indicated by a URI in the Location header field, which is intended to provide an indirect response to the original request."
    LOCATION_MISSING = {
        id: "location_missing",
        title: "A status that asks for Location carries none",
        message: "",
        default_severity: Severity::Warn,
        spec: &[
            RFC_9110_15_4_2,
            RFC_9110_15_4_3,
            RFC_9110_15_4_4,
            RFC_9110_15_4_8,
            RFC_9110_15_4_9,
        ],
    }

    /// A `Location` on a status that gives it no referent — anything but a
    /// `201` or a `3xx`.
    ///
    /// **`_redundant`, the ending that condemns nothing**, on
    /// `proxy_authenticate_redundant`'s reading: § 10.2.2 says the field is
    /// used in some responses and names which, and forbids the rest nowhere. So
    /// `_forbidden` would claim a prohibition that does not exist and
    /// `_invalid` a value that is fine. What the finding says is that the field
    /// is carrying a meaning by convention rather than by specification — a
    /// `202` pointing at a status monitor is the common case — and that the
    /// convention is now visible.
    ///
    /// **The exempt class is the whole of `3xx`**, because the licensing
    /// sentence names the class: a `304`, a deprecated `305`, and a 3xx nobody
    /// has registered are all exempt, the last because § 15 makes an
    /// unrecognized status the `x00` of its class to every conforming client.
    ///
    /// `info`, which is where `_redundant` starts.
    ///
    // cite(RFC 9110 § 10.2.2): "The "Location" header field is used in some responses to refer to a specific resource in relation to the response."
    LOCATION_REDUNDANT = {
        id: "location_redundant",
        title: "Location is sent on a status that gives it no referent",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_9110_10_2_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The absence costs a user agent its target; the presence costs nothing,
    /// and no sentence forbids it. That is the ranking, and there is no third
    /// consideration in it.
    #[test]
    fn the_absence_outranks_the_field_no_sentence_forbids() {
        assert_eq!(LOCATION_MISSING.default_severity, Severity::Warn);
        assert_eq!(LOCATION_REDUNDANT.default_severity, Severity::Info);
    }

    /// One entry names five sections and is therefore cited on none of them;
    /// the other names one and is cited. The rule is the same rule the whole
    /// catalogue uses, seen here at its clearest — the governing sentence
    /// depends on the status in front of the rule.
    #[test]
    fn the_entry_whose_sentence_depends_on_the_status_names_all_five() {
        assert_eq!(LOCATION_MISSING.spec.len(), 5);
        assert_eq!(LOCATION_REDUNDANT.spec.len(), 1);
    }
}
