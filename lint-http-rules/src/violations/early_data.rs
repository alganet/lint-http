// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Early-Data` defects — a field that carries one bit and says a great deal.
//!
//! RFC 8470 gives this field one job: an intermediary that forwarded a request
//! before its TLS handshake completed marks it, so the origin knows the request
//! may be a replay. That makes the entries here fall into two kinds, and the
//! ranking follows the split rather than the modal.
//!
//! **The two that matter are about what the mark means.** A request conveyed in
//! early data carrying a method whose safety is not known may take effect
//! twice; a field named as a connection option is stripped by the next
//! intermediary, which destroys the very signal the same section forbids
//! removing. Those are `warn`.
//!
//! **The two below them are about how the field is written, and § 5.1 says a
//! server reads it as `1` regardless.** A second field line and a value that is
//! not `1` both leave the request marked as early data exactly as the sender
//! meant; what is wrong is only the spelling, and the document says so in the
//! same breath as the rule. Those are `info`.
//!
//! Nothing about the *syntax* is here: the field is one octet compared against
//! one literal, so there is no production to borrow from.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// Using early data in clients: the MUST NOT on unsafe methods, and the
/// parenthesis that puts unknown-safety methods in the same set.
pub const RFC_8470_4: SpecRef = SpecRef {
    spec: "RFC 8470",
    section: Some("4"),
    url: "https://www.rfc-editor.org/rfc/rfc8470.html#section-4",
    note: "Using Early Data in HTTP Clients — the MUST NOT covering unsafe methods and methods whose safety is not known, opening with an \"Absent other information\" no message records",
};

/// The field itself: its one valid value, its one instance, what a server does
/// with a wrong one, and the two places it may not appear.
pub const RFC_8470_5_1: SpecRef = SpecRef {
    spec: "RFC 8470",
    section: Some("5.1"),
    url: "https://www.rfc-editor.org/rfc/rfc8470.html#section-5.1",
    note: "The Early-Data Header Field — one valid value, one instance added by an intermediary only where none is present, invalid or repeated instances read as a single \"1\", and the prohibitions on a Connection field, a response and a request trailer section",
};

defects! {
    /// An `Early-Data` field written where § 5.1 forbids it: named as a
    /// connection option in a `Connection` header field, or present in a
    /// response.
    ///
    /// **One entry over two sentences of one section, and the repair is the
    /// same** — delete the field from where it does not belong. The message
    /// says which, because the two cost different things and only one of them
    /// is dangerous.
    ///
    /// The `Connection` case is the one the entry exists for. Naming this field
    /// as a connection option has every intermediary strip it before
    /// forwarding, and the sentence immediately before the prohibition forbids
    /// an intermediary to remove it — so a deployment that writes it has
    /// arranged for the one signal an origin needs to disappear on the next
    /// hop. The response case is a request header field sent where there is
    /// nothing to mark, which says nothing and costs nothing.
    ///
    /// `error`, from § 5.1's two `MUST NOT`s, which are addressed to whoever
    /// wrote the field. A finding here can also mean the mark is gone, which is
    /// why the message says which shape it found.
    ///
    // cite(RFC 8470 § 5.1): "Early-Data MUST NOT appear in a Connection header field."
    // cite(RFC 8470 § 5.1): "An Early-Data header field MUST NOT be included in responses or request trailers."
    EARLY_DATA_FORBIDDEN = {
        id: "early_data_forbidden",
        title: "Early-Data appears where the section forbids it",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_8470_5_1],
        strength: Strength::Must,
    }

    /// A request marked as early data whose method is not one the deployment
    /// lists as safe.
    ///
    /// **The parenthesis is what makes an unrecognised method a finding.** § 4
    /// does not say "unsafe methods"; it says "unsafe methods (or methods whose
    /// safety is not known)", and a method this deployment has not listed is
    /// exactly the second kind. So the entry does not claim the method is
    /// unsafe — it claims nobody here knows that it is not, which is the state
    /// the sentence covers.
    ///
    /// What is at stake is the one thing early data costs: a request that
    /// arrives in it may arrive twice, and a method that changes state twice
    /// changes it twice.
    ///
    /// **The deployment's list is the measurement**, which is the same stand-in
    /// the registry entries in this catalogue make. RFC 9110 § 9.2.1 defines
    /// four safe methods and the IANA registry lists more, so a fixed set here
    /// would report conforming requests; the operator's array is the answer to
    /// the sentence's "absent other information".
    ///
    /// `error`: § 4 permits safe methods in early data and prohibits unsafe
    /// ones in the same sentence. The request is well formed and the origin may
    /// have information this proxy does not — which is a reason to configure
    /// the entry down, not a reason to rank it there.
    ///
    // cite(RFC 8470 § 4): "Absent other information, clients MAY send requests with safe HTTP methods ([RFC7231], Section 4.2.1) in early data when it is available and MUST NOT send unsafe methods (or methods whose safety is not known) in early data."
    EARLY_DATA_METHOD_FORBIDDEN = {
        id: "early_data_method_forbidden",
        title: "A request in early data uses a method whose safety is not known",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_8470_4],
        strength: Strength::Must,
    }

    /// More than one `Early-Data` field line in a request.
    ///
    /// The field holds a single bit, and the sentence that has an intermediary
    /// write it says it adds one *only where there is none*. A server reads the
    /// repeated lines as one instance with the value `1`, so the extra lines
    /// change nothing about the request or about how it is treated.
    ///
    /// `info` for exactly that: the mark arrives, the request is handled the
    /// way the sender meant, and what is left is a field line nobody reads.
    ///
    // cite(RFC 8470 § 5.1): "An intermediary that forwards a request prior to the completion of the TLS handshake with its client MUST send it with the Early-Data header field set to "1" (i.e., it adds it if not present in the request)."
    EARLY_DATA_DUPLICATED = {
        id: "early_data_duplicated",
        title: "A request carries more than one Early-Data field line",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_8470_5_1],
        strength: Strength::Unstated,
    }

    /// An `Early-Data` whose value is not the literal `1`.
    ///
    /// **`_invalid` rather than `_malformed`, and the field has no grammar to
    /// fail.** RFC 8470 gives it no ABNF at all — it gives it one valid value —
    /// so what a wrong value breaks is not a production but an enumeration of
    /// one. The octets are compared as octets, because equality with a literal
    /// is the only question asked of them.
    ///
    /// `info`, with the entry above and for the same reason: § 5.1 has a server
    /// treat an invalid instance as though it said `1`, so the request is
    /// marked as early data all the same and the value is simply wrong.
    ///
    // cite(RFC 8470 § 5.1): "It has just one valid value: "1"."
    EARLY_DATA_INVALID = {
        id: "early_data_invalid",
        title: "Early-Data carries a value other than 1",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_8470_5_1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The split this subject is ranked on: two findings about what the mark
    /// means, two about how it is spelled where § 5.1 says a server reads it as
    /// `1` regardless.
    #[test]
    fn what_the_mark_means_outranks_how_it_is_written() {
        for spelling in [&EARLY_DATA_DUPLICATED, &EARLY_DATA_INVALID] {
            for meaning in [&EARLY_DATA_FORBIDDEN, &EARLY_DATA_METHOD_FORBIDDEN] {
                assert!(
                    spelling.default_severity < meaning.default_severity,
                    "{} against {}",
                    spelling.id,
                    meaning.id
                );
            }
        }
    }
}
