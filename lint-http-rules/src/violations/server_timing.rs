// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Server-Timing` defects — the assembly of a metric's parameters, and what
//! the two established names mean.
//!
//! The field is `#server-timing-metric`, a metric is a `metric-name` and a
//! repetition of parameters, and almost all of that is borrowed: the list
//! floors are [`list`](crate::violations::list)'s, a `metric-name` and a
//! `server-timing-param-name` are [`token`](crate::violations::token)s, and a
//! value that is quoted is a
//! [`quoted_string`](crate::violations::quoted_string). The document says so
//! itself — *See `[RFC7230]` for definitions of #, \*, OWS, token, and
//! quoted-string* — and every one of those carried into RFC 9110 unchanged.
//!
//! **What is left is the assembly**, which is the residue a borrowed construct
//! leaves: a repetition that generates no bare semicolon, a `=` the production
//! prints between two halves it does not bracket, and a value half that derives
//! no empty string and no trailing content. None of them is a shape a borrowed
//! production can fail, and none can be borrowed from
//! [`parameter`](crate::violations::parameter): RFC 9110 § 5.6.6's value is
//! optional where this one is mandatory, and its Note forbids the whitespace
//! this production *prints*. **A production of the same shape in another
//! document is another production**, which is the line `Alt-Svc` drew one field
//! over and this document draws at a publisher that is not the IETF.
//!
//! **Every entry here names the section that prints the production, and none
//! names the modal.** The Server Timing specification holds nine BCP 14
//! keywords and eight of them are addressed to the user agent; the one that
//! measures a server is § 2's SHOULD NOT about a repeated parameter name. So
//! what makes a grammar defect reportable at all is RFC 9110 § 2.2 — *a sender
//! MUST NOT generate protocol elements that do not match the grammar* — and
//! that reference is the rule's rather than the entry's, the same way a port's
//! sixteen-bit width is. **The entry names the requirement; the reference that
//! supplies the modal stays where the rule declares it**, and the finding keeps
//! a citation it would lose if the entry named two.
//
// cite(Server Timing § 2, label: server-timing-metric assembly): "server-timing-metric = metric-name *( OWS ";" OWS server-timing-param )"

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The field's grammar and the two parameter names the document establishes.
pub const SERVER_TIMING_2: SpecRef = SpecRef {
    spec: "Server Timing",
    section: Some("2"),
    url: "https://www.w3.org/TR/server-timing/#the-server-timing-header-field",
    note: "The `Server-Timing` Header Field: the ABNF the entries here are written against, the two parameter names the specification establishes, and the user-agent parsing algorithm. Eight BCP 14 keywords: six addressed to the user agent, a MAY permitting a response to repeat a metric name, and a SHOULD NOT on a parameter name appearing twice in one metric — that last one is the only sentence in the whole document that measures what a server wrote. The section takes `#`, `*`, `OWS`, `token` and `quoted-string` from `[RFC7230]`, which is obsolete; the current productions are RFC 9110 § 5.6.1, § 5.6.3, § 5.6.2 and § 5.6.4 and are carried forward unchanged, so nothing decided here turns on which document is read. The document is a W3C Working Draft (7 April 2026) whose own Status section says \"It is inappropriate to cite this document as other than a work in progress\" — and it is nonetheless the field's only specification: the IANA HTTP Field Name Registry lists `Server-Timing` as **permanent** with this document as its sole reference, the same way it lists `Keep-Alive` against an obsoleted RFC. A work in progress is what there is to read",
};

defects! {
    /// A semicolon with no parameter behind it: `db; ;dur=5`, or a metric
    /// ending on one.
    ///
    /// `*( OWS ";" OWS server-timing-param )` repeats a group that holds one
    /// parameter and brackets nothing, so every semicolon the repetition
    /// generates owes a parameter after it. **A statement about a repetition's
    /// own shape**, which no borrowed construct can hold: the list's ids answer
    /// for the commas between metrics and there is no subject for the
    /// semicolons inside one.
    ///
    /// `_empty` rather than `_missing`: the semicolon is the repetition's
    /// delimiter, so a sender that wrote one knew a parameter was due.
    ///
    /// `warn`. Nothing is lost — a user agent reading leniently finds the same
    /// parameters — so what is reported is the writing rather than a
    /// consequence.
    ///
    // cite(Server Timing § 2, label: server-timing-param repetition): "server-timing-metric = metric-name *( OWS ";" OWS server-timing-param )"
    SERVER_TIMING_PARAM_EMPTY = {
        id: "server_timing_param_empty",
        title: "Server-Timing writes a semicolon with no parameter behind it",
        message: "",
        default_severity: Severity::Warn,
        spec: &[SERVER_TIMING_2],
    }

    /// A parameter written as a bare name: `db;desc`.
    ///
    /// `server-timing-param = server-timing-param-name OWS "=" OWS
    /// server-timing-param-value` prints all three parts and brackets none of
    /// them, so a name on its own is not a flag whose value is implied.
    ///
    /// **Not [`parameter_equals_missing`](crate::violations::parameter)**, for
    /// the reason that def's own subject records: it carries RFC 9110
    /// § 5.6.6's `parameter`, whose value the constructs reading it treat as
    /// optional, and whose Note forbids the whitespace *this* production prints
    /// around its `=`. Two documents, one shape, two sentences — and this one
    /// is not even an RFC.
    ///
    /// `warn`. The parameter is dropped, so the metric arrives saying less than
    /// the server wrote.
    ///
    // cite(Server Timing § 2, label: server-timing-param assembly): "server-timing-param = server-timing-param-name OWS "=" OWS server-timing-param-value"
    SERVER_TIMING_PARAM_EQUALS_MISSING = {
        id: "server_timing_param_equals_missing",
        title: "Server-Timing parameter has no '=' and no value",
        message: "",
        default_severity: Severity::Warn,
        spec: &[SERVER_TIMING_2],
    }

    /// An `=` with nothing after it: `db;desc=`.
    ///
    /// `server-timing-param-value = token / quoted-string` and neither
    /// alternative derives the empty string — a `token` is `1*tchar` and the
    /// shortest `quoted-string` is its two DQUOTEs. `desc=""` is a different
    /// value and conforms.
    ///
    /// **The shared reader of that alternation returns no id for an empty
    /// value on purpose**, because what one *means* is the field's to say and
    /// the fields reading it answered differently. Here it means a parameter
    /// whose whole content is its name.
    ///
    /// `warn`, beside [`SERVER_TIMING_PARAM_EQUALS_MISSING`] rather than folded
    /// into it: the `=` is the delimiter that tells the two apart, and a sender
    /// that wrote one knew a value was due.
    ///
    // cite(Server Timing § 2, label: server-timing-param-value alternation): "server-timing-param-value = token / quoted-string"
    SERVER_TIMING_PARAM_VALUE_EMPTY = {
        id: "server_timing_param_value_empty",
        title: "Server-Timing parameter is written with no value after its '='",
        message: "",
        default_severity: Severity::Warn,
        spec: &[SERVER_TIMING_2],
    }

    /// Content after the closing DQUOTE of a quoted value: `db;desc="abc"x`.
    ///
    /// The `quoted-string` is well formed and closed where it says; what
    /// derives from nothing is the *alternation* having content after one of
    /// its alternatives finished. That is `word`'s statement, and `word` owns
    /// no defect — an alternation is two productions and a choice between them,
    /// with nothing of its own to fail — so the field that assembled it is
    /// where the statement lands.
    ///
    /// **The document has a sentence about exactly this and it is addressed to
    /// the reader**: a user agent MUST ignore extraneous characters found after
    /// a value. Being told to ignore a thing is not being told one may write
    /// it, and what is silently dropped here is whatever the server meant by
    /// the tail.
    ///
    /// `_malformed`: the value as written derives from neither alternative,
    /// which is the word for a value the grammar does not generate. `warn`,
    /// with the rest of the assembly.
    ///
    // cite(Server Timing § 2, label: server-timing-param-value grammar under the field): "server-timing-param-value = token / quoted-string"
    SERVER_TIMING_PARAM_VALUE_MALFORMED = {
        id: "server_timing_param_value_malformed",
        title: "Server-Timing parameter value carries content past the alternative it derives from",
        message: "",
        default_severity: Severity::Warn,
        spec: &[SERVER_TIMING_2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::violations::parameter::PARAMETER_EQUALS_MISSING;

    /// The entries are the assembly and nothing else: each names the section
    /// that prints the production it fails, and none of them names the modal —
    /// RFC 9110 § 2.2 is what makes a grammar defect reportable when a document
    /// addresses every keyword it has to the recipient, and it stays on the
    /// rule so that these findings keep a citation.
    #[test]
    fn every_entry_names_the_production_and_none_names_the_modal() {
        for def in [
            &SERVER_TIMING_PARAM_EMPTY,
            &SERVER_TIMING_PARAM_EQUALS_MISSING,
            &SERVER_TIMING_PARAM_VALUE_EMPTY,
            &SERVER_TIMING_PARAM_VALUE_MALFORMED,
        ] {
            assert_eq!(def.spec, [SERVER_TIMING_2], "{}", def.id);
            assert_eq!(def.default_severity, Severity::Warn, "{}", def.id);
        }
    }

    /// The bare name is this field's defect and not the shared parameter
    /// subject's, because the productions disagree on whether the value is
    /// optional — which is the same disagreement that keeps `Alt-Svc` writing
    /// its own.
    #[test]
    fn the_bare_name_is_not_the_shared_parameters() {
        assert_ne!(
            SERVER_TIMING_PARAM_EQUALS_MISSING.id,
            PARAMETER_EQUALS_MISSING.id
        );
        assert_ne!(
            SERVER_TIMING_PARAM_EQUALS_MISSING.spec[0].spec,
            PARAMETER_EQUALS_MISSING.spec[0].spec
        );
    }
}
