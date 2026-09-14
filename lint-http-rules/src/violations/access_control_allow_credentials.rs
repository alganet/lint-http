// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `Access-Control-Allow-Credentials` defects — a field with one useful value,
//! and the two ways a response fails to share anything with credentials.
//!
//! The CORS check reads this field and compares it as bytes: `true` returns
//! success and every other value falls through to the algorithm's failure at
//! the end. There is no production to break — `false` is documented, and it
//! means exactly what omitting the field means — so the field has no
//! `_malformed` and cannot have one.
//!
//! **That is why there is no `_empty` entry here either**, and it is worth
//! saying because the sibling subject
//! [`access_control_allow_origin`](crate::violations::access_control_allow_origin)
//! has one and
//! [`origin_agent_cluster`](crate::violations::origin_agent_cluster) has one.
//! Both of those fields carry a production — three alternatives, a
//! structured-field boolean — under which an empty line derives from nothing at
//! all, which is a different failure from writing a well-formed value the
//! recipient declines. Here the recipient does not parse: it compares against
//! one byte sequence, and `""`, `false` and `TRUE` fail that comparison in the
//! same way, for the same reason, with the same repair.
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

defects! {
    /// The field is present and its value is not the byte sequence `true`:
    /// `false`, `TRUE`, `1`, an empty line, an octet.
    ///
    /// **`_invalid` rather than `_malformed`, because nothing here is parsed.**
    /// The check gets the field and compares it; a value that is not `true`
    /// falls through to the failure at the end of the algorithm. So this is not
    /// a value deriving from no production — there is no production — it is a
    /// field a server wrote in order to turn credentialed sharing on, which
    /// turns nothing on.
    ///
    /// **`TRUE` is the value this entry exists for.** The comparison here used
    /// to fold case, which told an operator that `TRUE` had enabled
    /// credentialed sharing and then reported the `*` pairing below for a
    /// combination no user agent ever reaches.
    ///
    // cite(Fetch § 4.10): "If credentials is `true`, then return success."
    ACCESS_CONTROL_ALLOW_CREDENTIALS_INVALID = {
        id: "access_control_allow_credentials_invalid",
        title: "Access-Control-Allow-Credentials states a value that is not `true`",
        message: "",
        default_severity: Severity::Warn,
        spec: &[FETCH_4_10],
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

    /// Both entries end the same way — the response shares nothing with
    /// credentials — so neither outranks the other. The difference between them
    /// is which field has to change, and the titles carry that.
    #[test]
    fn neither_entry_outranks_the_other() {
        assert_eq!(
            ACCESS_CONTROL_ALLOW_CREDENTIALS_INVALID.default_severity,
            ACCESS_CONTROL_ALLOW_CREDENTIALS_CONFLICTING.default_severity,
        );
    }

    /// The value entry leaves its message to the site: an operator reading it
    /// wants to know which value arrived. The pairing entry names both fields
    /// and no value, so it carries its whole message.
    #[test]
    fn only_the_entry_naming_a_value_leaves_its_message_to_the_site() {
        assert!(ACCESS_CONTROL_ALLOW_CREDENTIALS_INVALID.message.is_empty());
        assert!(!ACCESS_CONTROL_ALLOW_CREDENTIALS_CONFLICTING
            .message
            .is_empty());
    }

    /// The field has one useful value and no production, so no entry here may
    /// claim a grammar was broken — `_malformed` is the ending this subject
    /// cannot have.
    #[test]
    fn no_entry_claims_a_production_this_field_does_not_have() {
        for def in [
            &ACCESS_CONTROL_ALLOW_CREDENTIALS_INVALID,
            &ACCESS_CONTROL_ALLOW_CREDENTIALS_CONFLICTING,
        ] {
            assert!(!def.id.ends_with("_malformed"), "{}", def.id);
        }
    }
}
