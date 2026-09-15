// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Origin` defects — where a fetch says it came from.
//!
//! **The field's value is an alternation with a committing delimiter, and most
//! of what can be wrong with it belongs to somebody else.** `null` is a
//! literal; a `serialized-origin` is a scheme name, `://`, a host and an
//! optional port — so a bad scheme is
//! [`uri`](crate::violations::uri)'s scheme entries and an octet no URI is
//! composed from is that subject's too. What is left here is the two answers
//! the shared reader gives that no production owns.
//!
//! **One of them is the alternation's own limit.** *Derives from none of my
//! alternatives* is the finding a catalogue of productions cannot hold — there
//! is no production to blame, because the value reached none — and this
//! subject exists to hold it for this field.
//!
//! **The other is a component the production does not have.** A path after the
//! authority breaks nothing: the value derives from a perfectly good rule of
//! RFC 3986, just not from this one. That distinction is the whole point of the
//! field, which says where a request came from without saying what it was
//! reading.
//
// cite(RFC 6454 § 7.1): "origin-list-or-null = %x6E %x75 %x6C %x6C / origin-list"

use crate::helpers::uri::OriginDefect;
use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::{defects, ViolationDef};

/// The field's grammar: the two alternatives, and what a serialized origin is
/// made of.
pub const RFC_6454_7_1: SpecRef = SpecRef {
    spec: "RFC 6454",
    section: Some("7.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6454.html#section-7.1",
    note: "Origin header field syntax — `origin-list-or-null` is the literal `null` or a list of `serialized-origin`, and a `serialized-origin` is a scheme, `://`, a host and an optional port, with no path component",
};

/// What the header is for, and the fetches that carry it.
pub const FETCH_3_2: SpecRef = SpecRef {
    spec: "Fetch",
    section: Some("3.2"),
    url: "https://fetch.spec.whatwg.org/#origin-header",
    note: "The `Origin` request header — where a fetch originates from, sent for CORS fetches and for any request whose method is neither GET nor HEAD",
};

defects! {
    /// An `Origin` carrying a path: `https://example.com/app`.
    ///
    /// **Nothing is broken and that is the finding.** The value derives from a
    /// perfectly good rule of RFC 3986; it does not derive from *this* one,
    /// because `serialized-origin` has no path component at all. A recipient
    /// comparing origins byte for byte matches it against none.
    ///
    /// `_forbidden` rather than `_malformed`: the octets are all admissible and
    /// what refuses them is the production having no room for a component,
    /// which is the line this catalogue draws between the two endings.
    ///
    /// **This is the whole point of the field**, which says where a request
    /// came from without saying what it was reading — so a path here is a
    /// sender leaking the second while answering the first.
    ///
    // cite(RFC 6454 § 7.1): "serialized-origin = scheme "://" host [ ":" port ]"
    ORIGIN_PATH_FORBIDDEN = {
        id: "origin_path_forbidden",
        title: "An Origin names a path the production has no component for",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6454_7_1],
    }

    /// A value that is neither `null` nor anything a `serialized-origin`
    /// generates: no `://` at all, or an authority the host predicate refuses.
    ///
    /// **The entry that exists because a catalogue of productions cannot name
    /// this.** Every other reading of this field commits to an alternative and
    /// then fails inside it — a scheme that is not a scheme name, an octet no
    /// URI is composed from — and each of those belongs to the production it
    /// broke. Here the reading commits to nothing: `example.com` is not the
    /// literal `null` and never reaches a scheme, so there is no production
    /// whose entry could hold it.
    ///
    /// *An alternation owns no defect until the reading cannot commit* — the
    /// line `if_range_empty` drew — and this is that case for a field whose
    /// alternatives are a literal and a URI shape.
    ///
    // cite(RFC 6454 § 7.1): "origin-list-or-null = %x6E %x75 %x6C %x6C / origin-list"
    ORIGIN_MALFORMED = {
        id: "origin_malformed",
        title: "An Origin derives from neither null nor a serialized origin",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_6454_7_1],
    }

    /// A request that needs to say where it came from and does not: a CORS
    /// preflight, or a cross-origin request written in absolute form.
    ///
    /// **One entry for two gates, because the sender's mistake is one.** A
    /// preflight without an `Origin` and a cross-origin `absolute-form` request
    /// without one are found by different reasoning — the first from the method
    /// and the `Access-Control-Request-*` fields, the second by comparing the
    /// target's authority with the `Host` — and they leave a server the same
    /// way: asked to make a decision about an origin it was not told. The
    /// message says which gate found it.
    ///
    /// `warn`. The request is well formed and a server may answer it; what
    /// cannot happen is the CORS decision the request was asking for.
    ///
    // cite(Fetch § 3.2): "The `Origin` request header indicates where a fetch originates from."
    ORIGIN_MISSING = {
        id: "origin_missing",
        title: "A request that must say where it came from carries no Origin",
        message: "",
        default_severity: Severity::Warn,
        spec: &[FETCH_3_2],
    }
}

/// The defect a parsed [`OriginDefect`] reports as — all four of them.
///
/// **The mapping is total and it is split across two subjects**, which is what
/// the reader's shape asks for: two of its verdicts are somebody else's
/// production and answer to
/// [`uri`](crate::violations::uri::origin_production_defect), and two are this
/// field's. A caller asks here and gets an id either way, which is the state
/// this reader was converted to reach — while the field half had no entries the
/// answer was an `Option` and every caller worded the other half itself.
pub fn origin_defect(defect: OriginDefect<'_>) -> &'static ViolationDef {
    crate::violations::uri::origin_production_defect(defect).unwrap_or(match defect {
        OriginDefect::PathPresent => &ORIGIN_PATH_FORBIDDEN,
        _ => &ORIGIN_MALFORMED,
    })
}
