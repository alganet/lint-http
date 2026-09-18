// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Access-Control-Allow-Credentials` defects — a field with one generated
//! value, and the three ways a response fails to share anything with
//! credentials.
//!
//! **The field has a production, and it generates exactly one value.** Fetch
//! § 3.3.4 writes `Access-Control-Allow-Credentials = %s"true" ; case-sensitive`
//! among the ABNF for the CORS headers, so every other value — `TRUE`, `1`,
//! `false`, an empty line, an octet — derives from nothing. This module used to
//! say the opposite, that there was no production to break and that `false` was
//! documented. Fetch documents `Omitted`, `true` and `True`, in the table of
//! legal and illegal combinations at § 3.3.5; it never writes `false` at all.
//!
//! **What splits the value entries is intent, not grammar.** No value but
//! `true` derives, so grammar alone would put every one of them at one level.
//! But a sender that wrote `TRUE` meant to turn credentialed sharing on and did
//! not, and a sender that wrote `false` meant to leave it off and has — the
//! deployment's belief matches what the CORS check does. So the value the
//! sender got wrong is
//! [`_invalid`](ACCESS_CONTROL_ALLOW_CREDENTIALS_INVALID), graded from the
//! production, and the value the sender got right the long way is
//! [`_redundant`](ACCESS_CONTROL_ALLOW_CREDENTIALS_REDUNDANT), which condemns
//! nothing.
//!
//! **`_invalid` rather than `_malformed`, and an empty line stays inside it.**
//! The convention's ending for a value the ABNF does not generate is
//! `_malformed`, and the reason this subject keeps `_invalid` is the one
//! [`x_content_type_options`](crate::violations::x_content_type_options) gives
//! for the other single-literal field in this catalogue: the recipient does not
//! parse, it compares against one byte sequence, so nothing is read far enough
//! to break. That also answers why there is no `_empty` entry here, where the
//! sibling subjects
//! [`access_control_allow_origin`](crate::violations::access_control_allow_origin)
//! and [`origin_agent_cluster`](crate::violations::origin_agent_cluster) both
//! have one. Their productions have alternatives, so an empty line is a
//! distinct failure from a well-formed value the recipient declines. Here
//! `""`, `TRUE` and `1` fail the same comparison, for the same reason, with the
//! same repair, and separating them would report three names for one mistake.
//!
//! **The second entry is about a pairing, and it lives on this field rather
//! than on the origin.** `Access-Control-Allow-Origin: *` alone is a correct,
//! useful response; it becomes a finding only once this field claims `true`
//! beside it, because the CORS check succeeds on `*` only for a request whose
//! credentials mode is not "include". Delete this field and nothing is wrong.
//! So the field the claim is addressed to is the subject — the same call
//! [`content_length`](crate::violations::content_length) made for a message
//! framed two ways at once, reached here without a MUST NOT to point at: where
//! no document prohibits the pair, the field to name is the one whose statement
//! is the dead one.

use crate::lint::Severity;
use crate::lint::Strength;
use crate::rules::SpecRef;
use crate::violations::defects;

/// The CORS check: where the field is read, what the one value that returns
/// success is, and the step that makes `*` and credentials mutually exclusive.
pub const FETCH_4_10: SpecRef = SpecRef {
    spec: "Fetch",
    section: Some("4.10"),
    url: "https://fetch.spec.whatwg.org/#concept-cors-check",
    note: "Fetch CORS check — `*` succeeds only for non-credentialed requests, so `*` paired with `Access-Control-Allow-Credentials: true` can never authorize a credentialed request (the two cited steps)",
};

/// The production: the one value the field's ABNF generates, and the
/// case-sensitivity note the spec writes beside it.
pub const FETCH_3_3_4: SpecRef = SpecRef {
    spec: "Fetch",
    section: Some("3.3.4"),
    url: "https://fetch.spec.whatwg.org/#http-new-header-syntax",
    note: "`Access-Control-Allow-Credentials` value ABNF — one literal, byte case-sensitive, among the CORS header productions",
};

defects! {
    /// The field is present and its value is neither `true` nor `false`:
    /// `TRUE`, `1`, `yes`, an empty line, an octet.
    ///
    /// **`TRUE` is the value this entry exists for.** A server that writes this
    /// field at all has decided credentialed sharing should be on; a server
    /// that writes it and misses the one value the production generates has
    /// decided that and not got it. The deployment believes it shares responses
    /// with credentials, the CORS check falls through to the failure at the end
    /// of the algorithm, and every request that could have used the sharing is
    /// refused. The comparison here used to fold case, which told an operator
    /// that `TRUE` had worked and then reported the `*` pairing below for a
    /// combination no user agent ever reaches.
    ///
    /// `error`, from the production, which generates one value —
    /// [`Strength::Grammar`] and RFC 9110 § 2.2, the same reading
    /// [`x_content_type_options_invalid`](crate::violations::x_content_type_options::X_CONTENT_TYPE_OPTIONS_INVALID)
    /// takes on the other single-literal field here.
    ///
    /// **`false` is not this entry**, though it fails the same production. It
    /// is the one value outside the grammar whose sender got what they meant,
    /// and it is
    /// [`_redundant`](ACCESS_CONTROL_ALLOW_CREDENTIALS_REDUNDANT) below.
    ///
    // cite(Fetch § 3.3.4): "Access-Control-Allow-Credentials = %s"true" ; case-sensitive"
    // cite(Fetch § 4.10): "If credentials is `true`, then return success."
    ACCESS_CONTROL_ALLOW_CREDENTIALS_INVALID = {
        id: "access_control_allow_credentials_invalid",
        title: "Access-Control-Allow-Credentials was written to share with credentials and shares nothing",
        message: "",
        default_severity: Severity::Error,
        spec: &[FETCH_3_3_4, FETCH_4_10],
        strength: Strength::Grammar,
    }

    /// The field is present and its value is `false`.
    ///
    /// **The one value outside the production that costs nothing.** `false`
    /// does not derive from `%s"true"` any more than `TRUE` does, and Fetch
    /// never writes it — but the CORS check compares, falls through, and shares
    /// nothing with credentials, which is exactly what the sender asked for and
    /// exactly what omitting the field would have done. Nothing downstream
    /// behaves differently, no deployment believes something untrue, and the
    /// repair is to delete the line.
    ///
    /// **So this entry does not grade from the grammar, and says so.** The
    /// production is broken and RFC 9110 § 2.2 would put that at `error`; the
    /// claim being reported here is not that one. It is that the field states
    /// the default its own absence states, which is what `_redundant` is for
    /// and what no sentence anywhere obliges — hence [`Strength::Unstated`] and
    /// `info`, the level that ending takes unless there is an argument for
    /// more. There is not one: a reader who deletes the line and a reader who
    /// leaves it get the same protocol.
    ///
    // cite(Fetch § 3.3.4): "Access-Control-Allow-Credentials = %s"true" ; case-sensitive"
    ACCESS_CONTROL_ALLOW_CREDENTIALS_REDUNDANT = {
        id: "access_control_allow_credentials_redundant",
        title: "Access-Control-Allow-Credentials states the `false` its own absence states",
        message: "Access-Control-Allow-Credentials is 'false', which shares nothing with credentials — exactly what omitting the field does; delete the line",
        default_severity: Severity::Info,
        spec: &[FETCH_3_3_4, FETCH_4_10],
    }

    /// `true` on this field beside an `Access-Control-Allow-Origin` of `*`.
    ///
    /// The two are mutually exclusive by construction rather than by
    /// prohibition: the CORS check returns success on `*` only for a request
    /// whose credentials mode is *not* "include", and a credentialed request
    /// must instead match the byte-serialized origin — which `*` never is. So a
    /// server sending both is advertising a sharing it will never get, and
    /// every request that could have used it is refused.
    ///
    /// **`_conflicting` and not `_forbidden`**: no document forbids the pair.
    /// Each field is well-formed, each is honoured on its own, and what is
    /// wrong is that the two answers cannot both be acted on — which is the
    /// same shape as a response stating two freshness lifetimes.
    ///
    // cite(Fetch § 4.10): "If request’s credentials mode is not "include" and origin is `*`, then return success."
    ACCESS_CONTROL_ALLOW_CREDENTIALS_CONFLICTING = {
        id: "access_control_allow_credentials_conflicting",
        title: "Access-Control-Allow-Credentials claims `true` beside a wildcard origin",
        message: "Access-Control-Allow-Credentials must not be 'true' when Access-Control-Allow-Origin is '*'",
        default_severity: Severity::Warn,
        spec: &[FETCH_4_10],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All three entries end the same way — the response shares nothing with
    /// credentials — and they rank by what the sender still believes.
    ///
    /// The two that leave a deployment wrong about itself rank above the one
    /// that does not. `_invalid` and `_conflicting` are both a server
    /// advertising a sharing it will never get; `_redundant` is a server that
    /// asked for no sharing and got none, so it cannot outrank either.
    #[test]
    fn the_entry_whose_sender_got_what_they_asked_for_ranks_lowest() {
        assert!(
            ACCESS_CONTROL_ALLOW_CREDENTIALS_REDUNDANT.default_severity
                < ACCESS_CONTROL_ALLOW_CREDENTIALS_INVALID.default_severity,
        );
        assert!(
            ACCESS_CONTROL_ALLOW_CREDENTIALS_REDUNDANT.default_severity
                < ACCESS_CONTROL_ALLOW_CREDENTIALS_CONFLICTING.default_severity,
        );
    }

    /// Only the entry whose value *varies* leaves its message to the site: an
    /// operator reading it wants to know which value arrived, and it could have
    /// been anything. The other two each describe one fixed situation — a
    /// `false`, or a `true` beside a wildcard — so they carry their whole
    /// message and name no value the site has to supply.
    #[test]
    fn only_the_entry_whose_value_varies_leaves_its_message_to_the_site() {
        assert!(ACCESS_CONTROL_ALLOW_CREDENTIALS_INVALID.message.is_empty());
        assert!(!ACCESS_CONTROL_ALLOW_CREDENTIALS_REDUNDANT
            .message
            .is_empty());
        assert!(!ACCESS_CONTROL_ALLOW_CREDENTIALS_CONFLICTING
            .message
            .is_empty());
    }

    /// The production exists and generates one value, so exactly one entry here
    /// grades from it.
    ///
    /// This test replaces one that asserted the opposite — that the field had
    /// no production and so could carry no grammar reading. Fetch § 3.3.4
    /// writes one. What is still true is that `_malformed` is not this
    /// subject's ending, for the reason in the module doc: the recipient
    /// compares and never parses. So the shape to hold is that the grammar
    /// reading is stated once, on the value the sender got wrong, and that
    /// `false` is deliberately outside it.
    #[test]
    fn exactly_one_entry_grades_from_the_production() {
        assert_eq!(
            ACCESS_CONTROL_ALLOW_CREDENTIALS_INVALID.strength,
            Strength::Grammar,
        );
        for def in [
            &ACCESS_CONTROL_ALLOW_CREDENTIALS_REDUNDANT,
            &ACCESS_CONTROL_ALLOW_CREDENTIALS_CONFLICTING,
        ] {
            assert_ne!(def.strength, Strength::Grammar, "{}", def.id);
        }
        for def in [
            &ACCESS_CONTROL_ALLOW_CREDENTIALS_INVALID,
            &ACCESS_CONTROL_ALLOW_CREDENTIALS_REDUNDANT,
            &ACCESS_CONTROL_ALLOW_CREDENTIALS_CONFLICTING,
        ] {
            assert!(!def.id.ends_with("_malformed"), "{}", def.id);
        }
    }
}
