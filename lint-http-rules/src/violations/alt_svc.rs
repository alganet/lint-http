// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Alt-Svc` defects — what an alternative service advertisement says beyond
//! its grammar.
//!
//! The field is `1#alt-value`, an `alt-value` is `alternative *( OWS ";" OWS
//! parameter )`, and almost all of that is borrowed: the list floors are
//! [`list`](crate::violations::list)'s, the protocol identifier is an
//! [`alpn`](crate::violations::alpn) name, and a parameter's halves are
//! [`token`](crate::violations::token) and
//! [`quoted_string`](crate::violations::quoted_string). The `ma` parameter's
//! value is a [`delta_seconds`](crate::violations::delta_seconds), read at both
//! ends of that production.
//!
//! **What is left is what the field states for itself**, which is twelve
//! entries, and two of them are at opposite ends of it. One is the top
//! production's alternation, where the document names the state it forbids and
//! says what a recipient does about it. The other is what a number means: a freshness
//! lifetime that conforms to `delta-seconds` and cannot be what the sender
//! intended. RFC 7838 sets no bound in either direction — zero is a legal
//! `delta-seconds` and so is a run of forty digits — so that entry carries no
//! reference, and the message says which end of the range the value fell off.
//!
//! What `ma` states is a meaning rather than a bound, which is the whole of the
//! argument for the uncited entry; the alternation, by contrast, is a sentence,
//! and the entry naming it is cited on every finding.
//!
//! **The two `=` delimiters are here too, and they are the field's rather than
//! any production's.** `alternative` and `parameter` each print one, with
//! nothing beside it: RFC 7838 writes `OWS` in exactly one place — around the
//! semicolon before a parameter — and the `#rule` it imports writes it around
//! the commas, both of them gone by the time a half is read. So a delimiter
//! that is absent and whitespace that is present are two of this document's
//! sentences, and neither can borrow from
//! [`parameter`](crate::violations::parameter), whose § 5.6.6 production makes
//! the value optional and tolerates the whitespace at `info`. **A production of
//! the same name written in another document is another production.**
//!
//! **The `protocol-id`'s spelling is here as well, and it is one entry for
//! three sentences.** § 3 constrains the percent-encoding of an ALPN protocol
//! name three ways and says what for — *precisely one way to represent* it —
//! and every one of the three ends in the same place: two spellings of one name
//! where the recipient does simple string comparison. The name itself, once the
//! spelling is undone, is [`alpn`](crate::violations::alpn)'s.
//!
//! **The `alt-authority`'s three port entries are the prose rather than the
//! ABNF**, which is what makes them this subject's at all: the production is
//! `quoted-string` and a comment, and the sentence beside it asks for an
//! OPTIONAL host, a colon and a port number. Two of the three are not optional,
//! so a value with no colon, a value ending on one, and a value naming a number
//! no transport has are three senders with three fixes and one sentence between
//! them.
//!
//! **The last entry is the only one whose sentence is not § 3's or § 3.1's**:
//! § 8 tells a sender to write an internationalized domain name as A-labels, so
//! an octet at or above %x80 inside an `alt-authority` is reported with the
//! remedy rather than as an octet some production refused. With it the field's
//! rule declares nothing this catalogue has not read.
//
// cite(RFC 7838 § 3.1): "The delta-seconds value indicates the number of seconds since the response was generated for which the alternative service is considered fresh."

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// What the two parameters this document defines are for: how long an
/// advertisement stays fresh, and the one literal `persist` is allowed to
/// carry.
pub const RFC_7838_3_1: SpecRef = SpecRef {
    spec: "RFC 7838",
    section: Some("3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc7838.html#section-3.1",
    note: "Caching Alt-Svc Header Field Values: the `ma` parameter's delta-seconds value states how long the alternative is considered fresh, and `persist` has exactly one defined value — `\"1\"` — with clients required to ignore any other",
};

/// How a name that is not US-ASCII is written in this field, which is the one
/// requirement here that is about neither the grammar nor a parameter.
pub const RFC_7838_8: SpecRef = SpecRef {
    spec: "RFC 7838",
    section: Some("8"),
    url: "https://www.rfc-editor.org/rfc/rfc7838.html#section-8",
    note: "Internationalization Considerations: an internationalized domain name in this field is written as A-labels, which is what makes an octet at or above %x80 inside an `alt-authority` a defect with a remedy rather than only an octet no production admits",
};

/// The field: its grammar, the `clear` keyword, and what a recipient does with
/// a value carrying that keyword beside an alternative service.
pub const RFC_7838_3: SpecRef = SpecRef {
    spec: "RFC 7838",
    section: Some("3"),
    url: "https://www.rfc-editor.org/rfc/rfc7838.html#section-3",
    note: "The Alt-Svc HTTP Header Field: `Alt-Svc = clear / 1#alt-value` and the productions under it, the case-sensitive `clear` keyword, the three percent-encoding constraints on a `protocol-id`, and the prose requiring a colon and a port inside the `alt-authority`",
};

defects! {
    /// The keyword and an alternative service in one field value.
    ///
    /// `Alt-Svc = clear / 1#alt-value` is an alternation, so a value holding
    /// both halves derives from neither — and the document does not leave that
    /// to a reader to work out. It names the state in a parenthetical, calls it
    /// an invalid reply, and says what a client does with it: invalidate every
    /// alternative for the origin, *including the ones written beside the
    /// keyword*.
    ///
    /// `_conflicting` because both halves are readable and each one contradicts
    /// the other. Nothing is malformed at the octet level, nothing is missing,
    /// and neither half is forbidden on its own — what fails is that one field
    /// value says two things a recipient cannot both act on.
    ///
    /// **`error`, and it is the one entry in this subject that outranks its
    /// rule.** Every other defect in an `Alt-Svc` costs the sender the one
    /// alternative it is written in; this one costs the sender all of them,
    /// because the recipient's defined answer is to discard the alternatives
    /// this very response was sent to advertise. A field that is otherwise a
    /// hint here does the opposite of what its sender meant.
    ///
    // cite(RFC 7838 § 3): "A field value containing the special value "clear" indicates that the origin requests all alternatives for that origin to be invalidated (including those specified in the same response, in case of an invalid reply containing both "clear" and alternative services)."
    ALT_SVC_CLEAR_CONFLICTING = {
        id: "alt_svc_clear_conflicting",
        title: "Alt-Svc carries the clear keyword beside an alternative service",
        message: "",
        default_severity: Severity::Error,
        spec: &[RFC_7838_3],
    }

    /// An `alt-value` whose alternative holds no `=`: a protocol identifier
    /// and nowhere to reach it.
    ///
    /// `alternative = protocol-id "=" alt-authority` writes three parts and
    /// brackets none of them, so a member with no delimiter in it names a
    /// protocol and no service. What a recipient can do with it is nothing —
    /// the alternative is dropped, and the response advertises one fewer
    /// service than it looks like it does.
    ///
    /// **A `clear` in the wrong case reports here too, with its own message.**
    /// `%s"clear"` is RFC 7405's case-sensitive string, so `CLEAR` is not the
    /// keyword and is read as an `alt-value` like any other — which is exactly
    /// this defect, reached by a sender who meant something else entirely. The
    /// message says so; the id says what the value is. **A reading that
    /// explains how a sender got here is not a second defect**, which is the
    /// line drawn for the comma in a `Sec-WebSocket-Protocol`.
    ///
    /// `warn`, with the rest of the field's grammar: one alternative is lost
    /// and the exchange is unaffected, because a client that finds no
    /// alternative it can use goes to the origin.
    ///
    // cite(RFC 7838 § 3): "alternative   = protocol-id "=" alt-authority"
    ALT_SVC_ALTERNATIVE_EQUALS_MISSING = {
        id: "alt_svc_alternative_equals_missing",
        title: "Alt-Svc alternative has no '=' between its protocol-id and its alt-authority",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7838_3],
    }

    /// A `parameter` whose value and delimiter are both absent: `; ma`.
    ///
    /// **Not [`parameter_equals_missing`](crate::violations::parameter), and
    /// the reason is the whole of this entry.** That def carries RFC 9110
    /// § 5.6.6's `parameter`, whose `= value` half the constructs reading it
    /// treat as optional. This document prints `parameter = token "="
    /// ( token / quoted-string )` with no brackets anywhere in it, so a name on
    /// its own derives from nothing here and derives perfectly well there. **Two
    /// documents, one production name, two sentences** — borrowing the id would
    /// put § 5.6.6's requirement behind a finding § 5.6.6 does not make.
    ///
    /// Its own entry rather than the alternative's, for the same reason the two
    /// are two productions: what is absent differs. An `alternative` with no
    /// `=` names no service at all; a `parameter` with no `=` names a service
    /// perfectly well and loses one thing said about it.
    ///
    /// `warn`. A recipient that cannot read a parameter drops the alternative
    /// carrying it, since a member is read as a whole.
    ///
    // cite(RFC 7838 § 3): "parameter     = token "=" ( token / quoted-string )"
    ALT_SVC_PARAMETER_EQUALS_MISSING = {
        id: "alt_svc_parameter_equals_missing",
        title: "Alt-Svc parameter has no '=' and no value",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7838_3],
    }

    /// A repetition of the parameter group holding no parameter: `h2=":443"; ;`
    /// or a value ending on its semicolon.
    ///
    /// **Not [`list_member_empty`](crate::violations::list) and not
    /// [`parameter`](crate::violations::parameter)'s anything**, and the second
    /// half of that is the sharper one. § 5.6.6 writes `parameters = *( OWS ";"
    /// OWS [ parameter ] )` — the brackets are what make `text/plain;` a
    /// conforming zero-parameter repetition — and RFC 7838 § 3 writes
    /// `*( OWS ";" OWS parameter )` with no brackets at all. **The same
    /// repetition written without its brackets is a different production**, so
    /// what conforms one field over is a defect here, and the entry that would
    /// have been borrowed does not exist because there is nothing there to
    /// report.
    ///
    /// `_empty` and not `_missing`: the semicolon is the repetition's own
    /// delimiter, so a sender that wrote one knew a parameter was due and wrote
    /// none of it.
    ///
    /// `warn`, with the rest of the field's grammar — the alternative carrying
    /// it is what a recipient drops.
    ///
    // cite(RFC 7838 § 3): "Each "alt-value" is followed by an OPTIONAL semicolon-separated list of additional parameters, each such "parameter" comprising a name and a value."
    ALT_SVC_PARAMETER_EMPTY = {
        id: "alt_svc_parameter_empty",
        title: "Alt-Svc writes a semicolon with no parameter behind it",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7838_3],
    }

    /// An `=` with nothing after it: `ma=`.
    ///
    /// The value half is `( token / quoted-string )` and neither alternative
    /// derives the empty string — a `token` is `1*tchar` and the shortest
    /// `quoted-string` is its two DQUOTEs. `ma=""` is a different value and
    /// conforms to the production, whatever the parameter makes of it.
    ///
    /// **This entry is the answer to a `None` in a mapping.** The shared reader
    /// of `( token / quoted-string )` returns no id for an empty value on
    /// purpose, because what an empty value *means* is the field's to say and
    /// six fields reach that reader. Here it means an advertisement that named
    /// a parameter and said nothing with it, which is this document's sentence
    /// about its own production rather than § 5.6.6's about another one.
    ///
    /// `warn`, and beside [`ALT_SVC_PARAMETER_EQUALS_MISSING`] rather than
    /// folded into it: `docs/development.md` keeps `_missing` and `_empty`
    /// apart wherever a delimiter can tell them apart, and a sender that wrote
    /// the `=` knew a value was due.
    ///
    // cite(RFC 7838 § 3): "parameter     = token "=" ( token / quoted-string )"
    ALT_SVC_PARAMETER_VALUE_EMPTY = {
        id: "alt_svc_parameter_value_empty",
        title: "Alt-Svc parameter is written with no value after its '='",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7838_3],
    }

    /// Whitespace touching one of the field's two `=` delimiters: `h2 = ":443"`
    /// or `; ma = 60`.
    ///
    /// **One entry for both delimiters**, because what is forbidden is the same
    /// octet in the same position under the same sentence, and a sender that
    /// spaced out one of its `=` spaced out the other for the same reason. The
    /// message says which delimiter it was. **Split where the thing that is
    /// wrong differs, not where its container does.**
    ///
    /// RFC 7838 writes `OWS` in exactly one place — around the semicolon of
    /// `*( OWS ";" OWS parameter )` — and the `#rule` it imports writes it
    /// around the commas. Both are consumed before a half reaches a delimiter,
    /// so whitespace still touching an `=` is admitted by no production of this
    /// field. **This is the opposite answer to a `BWS`**, which is whitespace a
    /// grammar prints in order to tolerate; there is none printed here to
    /// tolerate.
    ///
    /// Which is also why this is not
    /// [`parameter_equals_whitespace_forbidden`](crate::violations::parameter).
    /// That entry is `info` because § 5.6.6's readers trim the whitespace and
    /// the specification publishes the leniency. Nothing publishes a leniency
    /// here, so the defect ranks with the field's other grammar defects at
    /// `warn` — a recipient reading `h2 ` against `token` finds no `tchar` for
    /// the space and drops the alternative.
    ///
    // cite(RFC 7838 § 3): "alt-value     = alternative *( OWS ";" OWS parameter )"
    ALT_SVC_EQUALS_WHITESPACE_FORBIDDEN = {
        id: "alt_svc_equals_whitespace_forbidden",
        title: "Alt-Svc writes whitespace beside an '=' its grammar prints bare",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7838_3],
    }

    /// An octet at or above %x80 anywhere inside an `alt-authority`:
    /// `h2="é.example.com:443"`.
    ///
    /// Every production the content derives from is US-ASCII — `reg-name` is
    /// `*( unreserved / pct-encoded / sub-delims )` and `port` is `*DIGIT` — so
    /// nothing here admits the octet wherever it sits. What makes the entry
    /// this field's rather than
    /// [`uri`](crate::violations::uri)'s is the sentence it reports: § 8 names
    /// the reason such an octet is usually there and says what to write
    /// instead, which is an A-label. **`uri_host_character_forbidden` would be
    /// true and would answer a different question** — that one says the octet
    /// derives from no `reg-name`, and this one says an internationalized
    /// domain name in *this* field is spelled some other way.
    ///
    /// It is also asked of the whole `alt-authority` before the colon is found,
    /// which is the second reason the host's entry cannot carry it: the octet
    /// may sit where a port would, and there is no host to have failed.
    ///
    /// `warn`, with everything else the alternative can be unreachable for.
    ///
    // cite(RFC 7838 § 8): "An internationalized domain name that appears in either the header field (Section 3) or the HTTP/2 frame (Section 4) MUST be expressed using A-labels ([RFC5890], Section 2.3.2.1)."
    ALT_SVC_AUTHORITY_CHARACTER_FORBIDDEN = {
        id: "alt_svc_authority_character_forbidden",
        title: "Alt-Svc alt-authority holds an octet no production of it admits",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7838_8],
    }

    /// An `alt-authority` with no colon in it: `h2="example.com"`.
    ///
    /// **The ABNF is not the requirement here, and that is the whole of these
    /// three entries.** `alt-authority = quoted-string` is followed by a
    /// comment, and the prose beside it is what states the shape: an OPTIONAL
    /// `uri-host`, a colon, and a port number. Two of the three are not
    /// optional, so a value naming a host and stopping names nothing a client
    /// can open a connection to — the same shape `authority-form` has, where
    /// the quantifiers demand nothing and the sentence beside them demands two
    /// halves.
    ///
    /// `_missing` and not `_empty`: no colon was written, so there is no port
    /// to be blank. [`ALT_SVC_PORT_EMPTY`] is the other side of that line.
    ///
    /// `warn`. The alternative is unusable and the origin still is not — a
    /// client with nowhere to reach the alternative uses the origin it already
    /// has.
    ///
    // cite(RFC 7838 § 3): "The "alt-authority" component consists of an OPTIONAL uri-host ("host" in Section 3.2.2 of [RFC3986]), a colon (":"), and a port number."
    ALT_SVC_PORT_MISSING = {
        id: "alt_svc_port_missing",
        title: "Alt-Svc alt-authority names no port",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7838_3],
    }

    /// An `alt-authority` that carries the colon and no digits after it:
    /// `h2="example.com:"`.
    ///
    /// `port` is `*DIGIT`, so the grammar derives this and there is no
    /// production to have broken; what asks for a number is § 3's prose. **The
    /// delimiter is what splits this from [`ALT_SVC_PORT_MISSING`]** — a sender
    /// that wrote the colon knew the component was there and wrote none of it,
    /// which is a different sender from one that stopped at the host.
    ///
    /// `warn`, with its sibling and for the same reason.
    ///
    // cite(RFC 7838 § 3): "The "alt-authority" component consists of an OPTIONAL uri-host ("host" in Section 3.2.2 of [RFC3986]), a colon (":"), and a port number."
    ALT_SVC_PORT_EMPTY = {
        id: "alt_svc_port_empty",
        title: "Alt-Svc alt-authority ends at the colon with no port",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7838_3],
    }

    /// An `alt-authority` naming a number no transport has: `h2=":65536"`.
    ///
    /// `port` is `*DIGIT` and bounds nothing at either end, so every digit here
    /// derives from the production and what fails is that the result is not a
    /// port number. **The sentence that makes it a defect is § 3's prose and
    /// the width comes from somewhere else** — § 2 says an ALPN protocol name
    /// implicitly identifies a suite carried over a transport, and those
    /// transports register their ports in a sixteen-bit namespace (RFC 6335
    /// § 6). So this entry names the requirement and the rule declaring it
    /// names the two references that supply the measurement: **a bound reached
    /// through a transport is still the requirement's defect, not the
    /// transport's**, which is the line the CONNECT destination's port drew one
    /// subject over.
    ///
    /// **`0` is not reported.** It sits inside the namespace as a reserved edge
    /// value, held back for extending the ranges later, and no sentence here
    /// makes a reserved port an invalid one.
    ///
    /// `_invalid` rather than `_malformed`, with this subject's other two: every
    /// octet is a DIGIT and the production is satisfied.
    ///
    // cite(RFC 7838 § 3): "The "alt-authority" component consists of an OPTIONAL uri-host ("host" in Section 3.2.2 of [RFC3986]), a colon (":"), and a port number."
    ALT_SVC_PORT_INVALID = {
        id: "alt_svc_port_invalid",
        title: "Alt-Svc alt-authority names a port no transport has",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7838_3],
    }

    /// A `protocol-id` that is a well-formed `token` of well-formed triplets
    /// and is not the one spelling this field allows for the name it stands
    /// for: `x%3dy` for `x%3Dy`, or `%68%32` for `h2`.
    ///
    /// § 3 states three constraints and states them for one declared purpose —
    /// *"In order to have precisely one way to represent any ALPN protocol
    /// name"*. Octets no `token` admits are percent-encoded, `%` itself is
    /// written `%25`, octets that *are* `tchar`s are not encoded at all, and
    /// the hex digits are uppercase. **A `token` admits `%`, so no character
    /// scan can see any of this**: every value reaching this entry has already
    /// derived from the production.
    ///
    /// **One entry for the constraints, because they are one requirement and
    /// the defect they describe is one defect.** Both spellings decode to the
    /// right name — that is what makes them spellings rather than errors — and
    /// what breaks is the closing sentence they exist for: *"recipients can
    /// apply simple string comparison to match protocol identifiers"*. A
    /// recipient comparing `%68%32` against `h2` finds two protocols where the
    /// sender meant one, whichever constraint was broken. The message says
    /// which triplet and why; the id says the name has more than one spelling.
    ///
    /// `_invalid`, on the same line `persist` is: every octet derives and what
    /// fails is one level past the grammar. `warn` — the alternative is
    /// advertised for a protocol no recipient will match, so it is lost the way
    /// an unreadable member is.
    ///
    // cite(RFC 7838 § 3): "In order to have precisely one way to represent any ALPN protocol name, the following additional constraints apply:"
    // cite(RFC 7838 § 3): "With these constraints, recipients can apply simple string comparison to match protocol identifiers."
    ALT_SVC_PROTOCOL_ID_INVALID = {
        id: "alt_svc_protocol_id_invalid",
        title: "Alt-Svc protocol-id is not the one spelling this field allows for its ALPN name",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_7838_3],
    }

    /// A `persist` parameter carrying anything but `1`.
    ///
    /// **The layer above a grammar**, and the second entry in this catalogue to
    /// live there: every production in sight derives `persist=2` — the name is
    /// a `token`, the value is a `token` — and what refuses it is the
    /// subsection that defines the parameter. § 3.1 prints one value and one
    /// only, and tells clients to ignore every other, so a value the grammar
    /// admits is a value the parameter does not have. `_invalid` is exactly
    /// that: grammatical, and refused past the grammar.
    ///
    /// **`info`, and the argument is the recipient's failure mode.** A client
    /// that ignores the parameter treats the alternative as *not* persistent,
    /// which is what an alternative with no `persist` at all is — the
    /// conservative reading, and the one a network change re-checks. So the
    /// sender lost a hint it wanted and nobody lost correctness, which is the
    /// same severity argument the qualified cache directives make one field
    /// over. It ranks below [`ALT_SVC_MA_INVALID`] for the same reason: an
    /// implausible lifetime is an advertisement a client will not use, and an
    /// unreadable `persist` is an advertisement it will use exactly as far as
    /// the next network change.
    ///
    // cite(RFC 7838 § 3.1): "This specification only defines a single value for "persist"."
    // cite(RFC 7838 § 3.1): "Clients MUST ignore "persist" parameters with values other than "1"."
    ALT_SVC_PERSIST_INVALID = {
        id: "alt_svc_persist_invalid",
        title: "Alt-Svc sets persist to a value the parameter does not define",
        message: "",
        default_severity: Severity::Info,
        spec: &[RFC_7838_3_1],
    }

    /// A freshness lifetime that derives from `delta-seconds` and states
    /// nothing a client can use: `ma=0`, which is stale on arrival, or a value
    /// so far above any deployment's horizon that it is a typo.
    ///
    /// **One entry for both ends, because the sender's mistake is one mistake**
    /// — the number written is not the number meant — and an operator who wants
    /// to hear about implausible lifetimes wants to hear about both. The message
    /// says which end, and for the upper one it names the bound it compared
    /// against rather than advising a smaller number.
    ///
    /// **Uncited, and this is the pair of reasons for it.** RFC 7838 § 3.1 gives
    /// `ma` a meaning and no bound: zero seconds is a conforming value that says
    /// the advertisement is already stale, which a sender is entitled to write,
    /// and nothing published states a maximum — so the upper end is this
    /// crate's own reading of where a policy stops being one. Both halves are
    /// sentences that do not exist, which is what an entry with no reference is
    /// for.
    ///
    /// `_invalid` rather than `_malformed`: every octet is a DIGIT and the
    /// production is satisfied. What fails is the value's usefulness, one level
    /// past the grammar.
    ///
    /// `warn`. Nothing is unreadable and no request is affected — the
    /// advertisement is simply not one a client will act on, which is a cost to
    /// the sender rather than to the exchange.
    ALT_SVC_MA_INVALID = {
        id: "alt_svc_ma_invalid",
        title: "Alt-Svc states a freshness lifetime that cannot be what was meant",
        message: "",
        default_severity: Severity::Warn,
        spec: &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entry that carries no sentence, and the reason it may not gain one
    /// later: what it reports is a value both of whose ends conform.
    #[test]
    fn the_uncited_entry_states_no_sentence() {
        assert!(ALT_SVC_MA_INVALID.spec.is_empty());
        assert_eq!(ALT_SVC_MA_INVALID.default_severity, Severity::Warn);
    }

    /// The two delimiters this field prints bare, measured against the
    /// `parameter` subject they may not borrow from: same shape, different
    /// document, and the rank is where the difference shows. § 5.6.6's readers
    /// trim the whitespace and the specification publishes the leniency, so
    /// that entry is `info`; nothing publishes one here.
    #[test]
    fn the_field_writes_its_own_delimiter_entries_rather_than_borrowing() {
        use crate::violations::parameter::{
            PARAMETER_EQUALS_MISSING, PARAMETER_EQUALS_WHITESPACE_FORBIDDEN,
        };

        assert_ne!(
            ALT_SVC_PARAMETER_EQUALS_MISSING.id,
            PARAMETER_EQUALS_MISSING.id
        );
        assert_eq!(
            ALT_SVC_EQUALS_WHITESPACE_FORBIDDEN.default_severity,
            Severity::Warn
        );
        assert_eq!(
            PARAMETER_EQUALS_WHITESPACE_FORBIDDEN.default_severity,
            Severity::Info
        );
        for def in [
            &ALT_SVC_ALTERNATIVE_EQUALS_MISSING,
            &ALT_SVC_PARAMETER_EQUALS_MISSING,
            &ALT_SVC_PARAMETER_EMPTY,
            &ALT_SVC_PARAMETER_VALUE_EMPTY,
            &ALT_SVC_EQUALS_WHITESPACE_FORBIDDEN,
        ] {
            assert_eq!(def.spec, [RFC_7838_3], "{}", def.id);
            assert_eq!(def.default_severity, Severity::Warn, "{}", def.id);
        }
    }

    /// The pair `docs/development.md` keeps apart wherever a delimiter can tell
    /// them apart, written here for both of the field's: the `;` of the
    /// repetition and the `=` of the parameter. A sender that wrote either knew
    /// something was due after it.
    #[test]
    fn each_delimiter_splits_the_absent_from_the_blank() {
        assert!(ALT_SVC_PARAMETER_EMPTY.id.ends_with("_empty"));
        assert!(ALT_SVC_PARAMETER_VALUE_EMPTY.id.ends_with("_empty"));
        assert!(ALT_SVC_PARAMETER_EQUALS_MISSING.id.ends_with("_missing"));
    }

    /// One sentence, three entries, and the reason they are three: a value with
    /// no colon, a value ending on one, and a value naming a number no
    /// transport has are three senders with three fixes. The delimiter is what
    /// splits the first two, exactly as it does for a CONNECT's destination —
    /// and the ranks are this field's rather than that one's, because an
    /// unusable alternative costs a client nothing it did not already have.
    #[test]
    fn the_alt_authoritys_prose_is_three_entries_of_one_rank() {
        use crate::violations::authority::AUTHORITY_TUNNEL_PORT_INVALID;

        for def in [
            &ALT_SVC_PORT_MISSING,
            &ALT_SVC_PORT_EMPTY,
            &ALT_SVC_PORT_INVALID,
        ] {
            assert_eq!(def.spec, [RFC_7838_3], "{}", def.id);
            assert_eq!(def.default_severity, Severity::Warn, "{}", def.id);
        }
        assert_eq!(
            AUTHORITY_TUNNEL_PORT_INVALID.default_severity,
            Severity::Error
        );
    }

    /// The two entries about a value that derives perfectly and is still wrong
    /// are the two `_invalid` ones, and they rank apart: a spelling nobody will
    /// match costs the alternative, and a `persist` nobody will read costs a
    /// hint. Neither is `_malformed`, which is the word for a value that does
    /// not derive at all.
    #[test]
    fn the_entries_past_the_grammar_are_the_invalid_ones() {
        assert_eq!(ALT_SVC_PROTOCOL_ID_INVALID.default_severity, Severity::Warn);
        assert!(
            ALT_SVC_PERSIST_INVALID.default_severity < ALT_SVC_PROTOCOL_ID_INVALID.default_severity
        );
        assert_eq!(ALT_SVC_PROTOCOL_ID_INVALID.spec, [RFC_7838_3]);
    }

    /// The two parameters § 3.1 defines rank apart, and the axis is what a
    /// recipient does when the value is no use: `persist` is ignored, which
    /// leaves the alternative exactly as persistent as one that never asked,
    /// where an implausible `ma` is an advertisement a client will not act on
    /// at all. Both cite the section that gives the parameters their meaning,
    /// or would — the lifetime's ends are the entry with no sentence.
    #[test]
    fn the_ignored_parameter_ranks_below_the_unusable_one() {
        assert_eq!(ALT_SVC_PERSIST_INVALID.default_severity, Severity::Info);
        assert!(ALT_SVC_PERSIST_INVALID.default_severity < ALT_SVC_MA_INVALID.default_severity);
        assert_eq!(ALT_SVC_PERSIST_INVALID.spec, [RFC_7838_3_1]);
        assert!(ALT_SVC_MA_INVALID.spec.is_empty());
    }

    /// The two entries are the subject's two ends, and they rank apart for a
    /// reason the file argues rather than assumes: a value nobody meant costs
    /// its own alternative, and a value the document calls an invalid reply
    /// costs every alternative the response carried.
    #[test]
    fn the_alternation_outranks_the_lifetime_and_names_its_sentence() {
        assert_eq!(ALT_SVC_CLEAR_CONFLICTING.default_severity, Severity::Error);
        assert_eq!(ALT_SVC_CLEAR_CONFLICTING.spec, [RFC_7838_3]);
        assert!(ALT_SVC_MA_INVALID.default_severity < ALT_SVC_CLEAR_CONFLICTING.default_severity);
    }
}
