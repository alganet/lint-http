// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Location` defects — a status that asked for the field, and a status the
//! field means nothing on.
//!
//! Two entries read by two rules from the two sides of one pairing: the field
//! is absent where a status's own definition asks for it, and present where no
//! definition gives it a referent. What the *value* is belongs to
//! [`uri`](crate::violations::uri), which `location_header_uri_valid` declares;
//! neither of those two entries reads a value at all.
//!
//! **The third does, and it is here because there is nothing in the value to
//! read.** An empty `Location` is a legal `URI-reference` — a same-document
//! reference resolving to the target URI — so no production refuses it and the
//! `uri` subject has no verdict to offer; what is wrong is that a field meant
//! to name a resource named the one already in hand.
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

/// Redirection: what a client is asked to do about a redirection that loops.
pub const RFC_9110_15_4: SpecRef = SpecRef {
    spec: "RFC 9110",
    section: Some("15.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4",
    note: "Redirection 3xx: a client SHOULD detect and intervene in cyclical redirections, and MAY follow a Location even where the specific status code is not understood",
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
    /// A `Location` that resolves to the target URI of the request it answers.
    ///
    /// **`_redundant`, and the vocabulary's own words fit it exactly**:
    /// permitted, and almost certainly not what was meant. No sentence forbids
    /// a response naming its own target; what § 15.4 does is ask the *client*
    /// to detect and intervene in cyclical redirections, and this is the
    /// shortest one there is — a client that obeys issues the request it just
    /// issued. The work the message does twice is the request itself.
    ///
    /// **`warn` rather than the `info` this ending starts at**, which is the
    /// argument the convention asks for on the page: the entry beside it costs
    /// a reader a moment's confusion, and this one costs a client a loop.
    ///
    /// Separated from [`LOCATION_REDUNDANT`] by its part rather than by a
    /// second ending: that entry is about the field being there at all on a
    /// status that gives it nothing to mean, this one about the redirect
    /// arriving where it started.
    ///
    // cite(RFC 9110 § 15.4): "A client SHOULD detect and intervene in cyclical redirections (i.e., "infinite" redirection loops)."
    LOCATION_REDIRECT_REDUNDANT = {
        id: "location_redirect_redundant",
        title: "A redirect names the target URI of the request it answers",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_9110_15_4],
    }

    /// A `Location` written and left blank.
    ///
    /// **Uncited, and it is the only entry in this subject with no sentence
    /// behind it — because there is none.** An empty value is a *legal*
    /// `URI-reference`: `relative-part` admits `path-empty`, which makes it a
    /// same-document reference resolving to the target URI, and neither
    /// RFC 9110 nor RFC 3986 forbids sending one. § 10.2.2 forbids nothing
    /// about this field in any case.
    ///
    /// What the entry reports is the operator's reading: a sender that writes
    /// `Location:` with nothing after it means to name a resource and named the
    /// one already in hand. On a redirect that is a user agent sent back where
    /// it started; anywhere else it is a field that states nothing.
    ///
    /// `info`, for a finding the documents permit outright — and level with
    /// [`content_location_empty`](crate::violations::content_location::CONTENT_LOCATION_EMPTY)
    /// and [`referer_empty`](crate::violations::referer::REFERER_EMPTY), which
    /// are the same empty reference in the two sibling fields carrying the same
    /// production. *Three fields reached this reading independently before any
    /// of them had an id; the ranks are equal because the value is the same
    /// value.*
    LOCATION_EMPTY = {
        id: "location_empty",
        title: "Location is written with nothing in it",
        message: "",
        default_severity: Severity::Info,
        spec: &[],
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

    /// Two entries share the ending that condemns nothing, and they are told
    /// apart by their part and by their severity: one costs a reader a
    /// moment's confusion, the other costs a client a loop.
    #[test]
    fn the_two_redundancies_differ_by_part_and_by_what_they_cost() {
        assert!(LOCATION_REDUNDANT.id.ends_with("_redundant"));
        assert!(LOCATION_REDIRECT_REDUNDANT.id.ends_with("_redundant"));
        assert!(LOCATION_REDUNDANT.default_severity < LOCATION_REDIRECT_REDUNDANT.default_severity);
    }

    /// The empty reference is one value in three fields, so the three entries
    /// that report it rank together — and this one names no sentence at all,
    /// which is what separates it from every other entry in the subject.
    #[test]
    fn the_empty_reference_ranks_the_same_way_in_all_three_fields() {
        assert!(LOCATION_EMPTY.spec.is_empty());
        assert_eq!(
            LOCATION_EMPTY.default_severity,
            crate::violations::content_location::CONTENT_LOCATION_EMPTY.default_severity
        );
        assert_eq!(
            LOCATION_EMPTY.default_severity,
            crate::violations::referer::REFERER_EMPTY.default_severity
        );
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
