// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{combined_field_value_as_written, trim_ows};
use crate::helpers::list::{
    list_members_as_written, quoting_is_balanced, split_semicolons_respecting_quotes,
};
use crate::helpers::shown::shown_in_finding;
use crate::helpers::word::token_or_quoted_string;
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

/// Alt-Svc advertising `h3` must use the final protocol ID (not draft versions),
/// with a reasonable `ma` (max-age) value (RFC 9114 §3.1.1, RFC 7838).
pub struct AltSvcH3AdvertisementValid;

/// The alternative of the field's top production that is not a list.
///
/// `%s` is RFC 7405's case-sensitive string, so `Clear` is not this keyword —
/// which costs this rule nothing either way, since a value that is not an
/// `alt-value` advertises no HTTP/3 endpoint. Spelled the same way as
/// `alt_svc_header_syntax`'s, because it is the same literal.
// cite(RFC 7838 § 3, label: Alt-Svc grammar): "Alt-Svc       = clear / 1#alt-value"
// cite(RFC 7838 § 3): "clear         = %s"clear"; "clear", case-sensitive"
const CLEAR: &str = "clear";

/// The one `ma` this document defines, and it is not folded.
///
/// RFC 7838 prints `parameter = token "=" ( token / quoted-string )` and states
/// nothing about comparing a parameter name without regard to case. RFC 9110
/// § 5.6.6's *"Parameter names are case-insensitive"* governs the `parameters`
/// production, which this field does not import — it writes its own — so it does
/// not reach here, and `alt_svc_header_syntax` already compares `persist`
/// case-sensitively for the same reason. What a recipient does with `MA` is
/// § 3's *"Unknown parameters MUST be ignored."*, so a finding about `MA=0`
/// invalidating an advertisement would be describing something that does not
/// happen.
// cite(RFC 7838 § 3): "parameter     = token "=" ( token / quoted-string )"
// cite(RFC 7838 § 3): "Unknown parameters MUST be ignored."
const MA: &str = "ma";

/// Maximum reasonable max-age: 1 year in seconds. RFC 7838 sets **no** upper
/// bound on `ma`; this is a linter heuristic to flag likely misconfiguration,
/// not a spec limit — hence uncited (recorded in the audit ledger, §4.1).
const MAX_REASONABLE_MA: u64 = 365 * 24 * 3600;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9114_3_1_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9114",
    section: Some("3.1.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-3.1.1",
    note: "HTTP Alternative Services — advertising HTTP/3 via Alt-Svc using the \"h3\" ALPN token",
};
const RFC_7838_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 7838",
    section: Some("3"),
    url: "https://www.rfc-editor.org/rfc/rfc7838.html#section-3",
    note: "Alt-Svc — the field's grammar, the `parameter` production, and the requirement that a recipient ignore a parameter name it does not know",
};
const RFC_7838_3_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 7838",
    section: Some("3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc7838.html#section-3.1",
    note:
        "Caching Alt-Svc Header Field Values — what the `ma` parameter's delta-seconds value means",
};
const RFC_9111_1_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("1.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-1.2.2",
    note: "delta-seconds — the `1*DIGIT` production `ma` carries, and what a cache does with a value too large to represent",
};

impl RuleMeta for AltSvcH3AdvertisementValid {
    fn id(&self) -> &'static str {
        "alt_svc_h3_advertisement_valid"
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Alt-Svc H3 Advertisement Valid")
    }

    fn description(&self) -> &'static str {
        "Reads the `Alt-Svc` response header field for the entries that advertise HTTP/3, and asks two things of each: that it names the shipped protocol, and that the freshness lifetime it carries is one.\n\n**The protocol identifier.** RFC 9114 §3.1.1: *\"An HTTP origin can advertise the availability of an equivalent HTTP/3 endpoint via the Alt-Svc HTTP response header field or the HTTP/2 ALTSVC frame ([ALTSVC]) using the \"h3\" ALPN token.\"* A draft-era token — `h3-29`, `h3-Q050`, `h3-27` — is a different ALPN protocol name, so a client that speaks HTTP/3 and not that draft finds nothing it can use at the alternative.\n\n**The `ma` parameter.** RFC 7838 §3.1 gives it a `delta-seconds` value, and `delta-seconds` is `1*DIGIT` (RFC 9111 §1.2.2) — **the production, not an integer type**. A leading `+` is not part of it, so `ma=+5` is reported even though every standard-library parser reads it as 5; conversely a run of digits longer than 64 bits is a conforming value that RFC 9111 §1.2.2 tells a cache to clamp rather than reject, so it is measured against this rule's ceiling instead of being called malformed. `ma=0` is fresh for zero seconds — the advertisement is stale as it arrives — and is reported as the likely misconfiguration it is.\n\n**The ceiling is a heuristic and is the one thing here with no sentence behind it.** RFC 7838 places no upper bound on `ma`. One year (31 536 000 seconds) is this linter's guess at where a value stops being a policy and starts being a typo.\n\n**The parameter name is compared case-sensitively, and the protocol identifier is not.** RFC 7838 prints `parameter = token \"=\" ( token / quoted-string )` and states no case-insensitivity for the name; RFC 9110 §5.6.6's *\"Parameter names are case-insensitive\"* governs the `parameters` production, which this field does not import. So `MA=0` is a parameter name a client is required to ignore (*\"Unknown parameters MUST be ignored.\"*), and reporting it as invalidating an advertisement would describe something that does not happen. The **protocol identifier** is folded to lowercase, deliberately and against §3's *\"simple string comparison\"*: the fold only ever widens what this rule reports, so `H3-29` is still named as a draft token and `H3=…; ma=0` is still measured.\n\n**What this rule leaves to its two siblings.** Everything about the field's shape is `alt_svc_header_syntax`'s, on every protocol rather than on `h3` alone: an empty list element, an `alternative` with no `=`, an empty `protocol-id`, a percent-encoding this field's one-spelling constraints forbid, a `parameter` with no value or a value that is neither a `token` nor a well-formed `quoted-string`, and an unterminated DQUOTE — which this rule treats as making the whole value unreadable rather than guessing at where its members end. Whether the ALPN name is registered is `alt_svc_protocol_registered`'s.\n\nThe field lines are joined before they are read (RFC 9110 §5.3), because `1#alt-value` is the list that licenses the join, and the value is read one `char` per octet so that an `obs-text` octet is measured rather than hiding the line it is written on."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9114_3_1_1, RFC_7838_3, RFC_7838_3_1, RFC_9111_1_2_2]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("The shipped ALPN token, with a freshness lifetime"),
                snippet: "Alt-Svc: h3=\":443\"; ma=2592000",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("No `ma` at all: the parameter is optional"),
                snippet: "Alt-Svc: h3=\":443\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("An `h3` entry beside another protocol's"),
                snippet: "Alt-Svc: h2=\":443\", h3=\":443\"; ma=3600",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "A parameter name this document does not define is ignored, not folded",
                ),
                snippet: "Alt-Svc: h3=\":443\"; MA=0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A draft protocol identifier"),
                snippet: "Alt-Svc: h3-29=\":443\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Fresh for zero seconds: stale as it arrives"),
                snippet: "Alt-Svc: h3=\":443\"; ma=0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Beyond the one-year ceiling this linter guesses at"),
                snippet: "Alt-Svc: h3=\":443\"; ma=99999999",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("No `delta-seconds`: `1*DIGIT` writes no sign"),
                snippet: "Alt-Svc: h3=\":443\"; ma=+5",
            },
        ]
    }
}

impl Rule for AltSvcH3AdvertisementValid {
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            let resp = tx.response.as_ref()?;

            // The field probe before the config, and the value read as the sender
            // wrote it — one `char` per octet. The `to_str()` + `continue` this
            // replaced dropped every field line carrying an octet at or above
            // %x80, which is the octet class no `token` admits: the one spelling of
            // a protocol-id that certainly derives from nothing was the one
            // spelling this rule could not see.
            //
            // The lines are joined rather than read one at a time, because the
            // sentence cited below makes them one value and `1#alt-value` is the
            // list that licenses the join — an `alt-value` is not a `clear`, which
            // is the field's other alternative and is ruled out under it. The
            // header section only: what may ride in a trailer section is
            // § 6.5.1's question and `trailer_fields_valid`'s finding.
            //
            // cite(RFC 7838 § 3): "An HTTP(S) origin server can advertise the availability of alternative services to clients by adding an Alt-Svc header field to responses."
            // cite(RFC 9110 § 5.3): "A recipient MAY combine multiple field lines within a field section that have the same field name into one field line, without changing the semantics of the message, by appending each subsequent field line value to the initial field line value in order, separated by a comma (",") and optional whitespace (OWS, defined in Section 5.6.3)."
            let value = combined_field_value_as_written(&resp.headers, "alt-svc")?;
            let value = trim_ows(&value);

            // The other alternative of the top production, which advertises no
            // endpoint of any protocol. A `clear` sharing the value with alternative
            // services is `alt_svc_header_syntax`'s finding, and this rule
            // reads the alternatives beside it the same way a client does.
            if value == CLEAR {
                return None;
            }

            // An unterminated DQUOTE makes every separator after it ambiguous, so
            // the member list is a guess and so is each member's parameter list.
            // The syntax rule reports it; nothing below can be said about a value
            // whose shape is unknown.
            if !quoting_is_balanced(value) {
                return None;
            }

            for member in list_members_as_written(value) {
                // An empty list element and a member with no '=' are both
                // `alt_svc_header_syntax`'s findings; this rule has no
                // alternative to read in either.
                if member.is_empty() {
                    continue;
                }
                let parts = split_semicolons_respecting_quotes(member);
                let (alternative, parameters) = parts
                    .split_first()
                    .expect("the splitter yields at least one segment");
                let Some((protocol_id, _)) = alternative.split_once('=') else {
                    continue;
                };
                if protocol_id.is_empty() {
                    continue;
                }

                // RFC 7838 §3 says protocol-ids are matched by "simple string
                // comparison" (case-sensitive); this rule folds to lowercase — a
                // deliberate, more-permissive choice so case-variant draft tokens
                // (e.g. "H3-29") are still flagged. Not cited: the spec sentence
                // mandates case-sensitive comparison, which is not what this does
                // (the #10 shape — permissive code, no honest quote; §4.1). The
                // fold **widens** what is reported on both of its uses, which is
                // what makes it recordable as a leniency rather than an invented
                // licence: `H3-29` is still named as a draft token, and `H3=…; ma=0`
                // is still measured.
                let proto_lower = protocol_id.to_ascii_lowercase();

                // Draft h3 protocol IDs (h3-29, h3-Q050, etc.): the final ALPN token
                // advertised for HTTP/3 is "h3", so any "h3-*" draft token is not a
                // valid advertisement of the shipped protocol.
                // cite(RFC 9114 § 3.1.1): "An HTTP origin can advertise the availability of an equivalent HTTP/3 endpoint via the Alt-Svc HTTP response header field or the HTTP/2 ALTSVC frame ([ALTSVC]) using the "h3" ALPN token."
                if proto_lower.starts_with("h3-") {
                    return Some(self.cited(&RFC_9114_3_1_1,
                        ctx.severity,
                        format!(
                            "Alt-Svc uses draft HTTP/3 protocol identifier '{}'; use the final 'h3' token instead (RFC 9114 §3.1.1)",
                            shown_in_finding(protocol_id)
                        ),
                    ));
                }

                // Only validate parameters for actual h3 entries
                if proto_lower != "h3" {
                    continue;
                }

                if let Some(message) = h3_ma_defect(parameters) {
                    return Some(self.violation(ctx.severity, message));
                }
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// The reason this h3 entry's `ma` parameter does not advertise a freshness
/// lifetime, or `None`.
///
/// `parameters` are the segments after the `alternative`, already split on the
/// semicolons a `quoted-string` does not swallow.
///
/// The value half is `( token / quoted-string )` and is read by the shared
/// reader that owns the alternation, so `ma="86400"` and `ma=86400` are the
/// same value and `ma="864\00"` is the value `86400` — which the hand-written
/// `starts_with('"') && ends_with('"')` strip this replaced could not say, and
/// which it read as the two-character-shorter string on an unbalanced quote.
///
/// A `parameter` this rule cannot read at all — no `=`, an empty value, a
/// malformed `quoted-string` — is `alt_svc_header_syntax`'s finding, on
/// every protocol rather than on `h3` alone, so it is passed over here rather
/// than reported twice in different words.
// cite(RFC 7838 § 3): "parameter     = token "=" ( token / quoted-string )"
// cite(RFC 7838 § 3): "Each "alt-value" is followed by an OPTIONAL semicolon-separated list of additional parameters, each such "parameter" comprising a name and a value."
fn h3_ma_defect(parameters: &[&str]) -> Option<String> {
    for parameter in parameters {
        // Whitespace beside the '=' leaves it in the name, so `ma = 0` does not
        // match and is not measured here. That is the right answer rather than a
        // gap: `alternative` and `parameter` print no `OWS` around their
        // delimiters, so such a segment derives from no `parameter` at all and
        // is already reported as that by `alt_svc_header_syntax`.
        let Some((name, value)) = parameter.split_once('=') else {
            continue;
        };
        if name != MA {
            continue;
        }
        let Ok(seconds) = token_or_quoted_string(value) else {
            continue;
        };

        // `ma` carries a delta-seconds count — how long the advertisement stays
        // fresh — and `delta-seconds` is `1*DIGIT`. That is the production, not
        // an integer type: `parse::<u64>()` accepts a leading '+', which no
        // `1*DIGIT` writes, and refuses a run of digits longer than 64 bits,
        // which is a conforming value the document tells a cache how to handle.
        // So the characters are measured against the production first and only
        // then read as a number.
        // cite(RFC 7838 § 3.1): "The delta-seconds value indicates the number of seconds since the response was generated for which the alternative service is considered fresh."
        // cite(RFC 9111 § 1.2.2, label: delta-seconds): "delta-seconds  = 1*DIGIT"
        // cite(RFC 9111 § 1.2.2): "The delta-seconds rule specifies a non-negative integer, representing time in seconds."
        if seconds.is_empty() || !seconds.chars().all(|c| c.is_ascii_digit()) {
            return Some(format!(
                "Alt-Svc h3 entry has 'ma={}', which is no `delta-seconds`: the production is `1*DIGIT` (RFC 9111 §1.2.2), so a sign, a radix point or any other character leaves the freshness lifetime unstated",
                shown_in_finding(&seconds)
            ));
        }

        // Every character is a digit by now, so the only way the parse fails is
        // a run longer than 64 bits — a value the document has a cache clamp
        // rather than reject, and one this rule's ceiling already covers.
        // cite(RFC 9111 § 1.2.2): "If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648"
        // cite(RFC 9111 § 1.2.2): "or the greatest positive integer it can conveniently represent."
        let n = seconds.parse::<u64>().unwrap_or(u64::MAX);

        if n == 0 {
            return Some(
                "Alt-Svc h3 entry has 'ma=0' which immediately invalidates the advertisement (RFC 7838 §3.1)"
                    .into(),
            );
        }
        // Heuristic ceiling, not spec-derived: RFC 7838 places no upper bound
        // on `ma` (see MAX_REASONABLE_MA). Flags likely misconfiguration only.
        if n > MAX_REASONABLE_MA {
            return Some(format!(
                "Alt-Svc h3 entry has unreasonably large 'ma={}' (exceeds 1 year / {} seconds)",
                shown_in_finding(&seconds),
                MAX_REASONABLE_MA
            ));
        }
    }

    None
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &AltSvcH3AdvertisementValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    // No violation cases
    #[case(None, false)]
    #[case(Some("h3=\":443\"; ma=2592000"), false)]
    #[case(Some("h3=\":443\""), false)]
    #[case(Some("h3=example.com:443; ma=86400"), false)]
    #[case(Some("h2=\":443\", h3=\":443\"; ma=3600"), false)]
    #[case(Some("h3=\":443\"; ma=\"86400\""), false)]
    #[case(Some("h2=\":443\""), false)]
    #[case(Some("clear"), false)]
    #[case(Some("h3=\":443\"; ma=31536000"), false)]
    // Draft version violations
    #[case(Some("h3-29=\":443\""), true)]
    #[case(Some("h3-Q050=\":443\""), true)]
    #[case(Some("h3-27=\":443\"; ma=3600"), true)]
    #[case(Some("h2=\":443\", h3-29=\":443\""), true)]
    // ma=0 violation
    #[case(Some("h3=\":443\"; ma=0"), true)]
    #[case(Some("h3=\":443\"; ma=\"0\""), true)]
    // Unreasonably large ma
    #[case(Some("h3=\":443\"; ma=99999999"), true)]
    #[case(Some("h3=\":443\"; ma=31536001"), true)]
    // No `delta-seconds`: the production is `1*DIGIT` and nothing else.
    #[case(Some("h3=\":443\"; ma=abc"), true)]
    // `parse::<u64>()` read this as 5; no `1*DIGIT` writes a sign.
    #[case(Some("h3=\":443\"; ma=+5"), true)]
    #[case(Some("h3=\":443\"; ma=8.6e4"), true)]
    // Every character is a digit and the run is longer than 64 bits — a value
    // §1.2.2 has a cache clamp rather than reject. Reported for the ceiling,
    // which is what it exceeds, and not as "non-numeric".
    #[case(Some("h3=\":443\"; ma=99999999999999999999999"), true)]
    // A `quoted-pair` is the octet after the backslash, so this is 86400.
    #[case(Some("h3=\":443\"; ma=\"864\\00\""), false)]
    // An empty value derives from neither half of `( token / quoted-string )`,
    // and saying so is `alt_svc_header_syntax`'s finding on every
    // protocol rather than this rule's on `h3`.
    #[case(Some("h3=\":443\"; ma="), false)]
    // The protocol-id fold, which widens: a case-variant draft token is still
    // named, and a case-variant `h3` is still measured.
    #[case(Some("H3=\":443\"; ma=86400"), false)]
    #[case(Some("H3=\":443\"; ma=0"), true)]
    // The parameter name is **not** folded. RFC 7838 states no
    // case-insensitivity for it and §3 has a client ignore a name it does not
    // know, so `MA=0` invalidates nothing and reporting it would describe
    // something that does not happen.
    #[case(Some("h3=\":443\"; MA=86400"), false)]
    #[case(Some("h3=\":443\"; MA=0"), false)]
    // Whitespace beside the '=' leaves it in the name; the segment derives from
    // no `parameter` and the syntax rule is what reports it.
    #[case(Some("h3=\":443\"; ma = 0"), false)]
    // An unterminated DQUOTE makes every separator after it a guess.
    #[case(Some("h3=\":443\"; ma=\"0"), false)]
    // Persist param without ma (valid, defaults to 24h)
    #[case(Some("h3=\":443\"; persist=1"), false)]
    // Multiple params including valid ma
    #[case(Some("h3=\":443\"; persist=1; ma=86400"), false)]
    // Boundary: ma=1 is valid (positive)
    #[case(Some("h3=\":443\"; ma=1"), false)]
    // Negative ma value (non-numeric)
    #[case(Some("h3=\":443\"; ma=-1"), true)]
    // CLEAR directive (case-insensitive)
    #[case(Some("CLEAR"), false)]
    // Draft with numeric suffix only
    #[case(Some("h3-14=\":443\""), true)]
    // h3 mixed with clear
    #[case(Some("clear, h3=\":443\"; ma=86400"), false)]
    // Quoted parameter value containing semicolon should not mis-split
    #[case(Some("h3=\":443\"; foo=\"a;b\"; ma=86400"), false)]
    fn check_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = AltSvcH3AdvertisementValid;
        let tx = match header {
            Some(h) => {
                crate::test_helpers::make_test_transaction_with_response(200, &[("alt-svc", h)])
            }
            None => crate::test_helpers::make_test_transaction_with_response(200, &[]),
        };

        let config = crate::test_helpers::make_test_config_with_severity(
            "alt_svc_h3_advertisement_valid",
            "warn",
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for header={:?}", header);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for header={:?}: {:?}",
                header,
                v
            );
        }
    }

    #[test]
    fn draft_version_message_includes_protocol() {
        let rule = AltSvcH3AdvertisementValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "h3-29=\":443\"")],
        );
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        )
        .unwrap();
        assert!(v.message.contains("h3-29"));
        assert!(v.message.contains("draft"));
    }

    #[test]
    fn ma_zero_message_mentions_invalidation() {
        let rule = AltSvcH3AdvertisementValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "h3=\":443\"; ma=0")],
        );
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        )
        .unwrap();
        assert!(v.message.contains("ma=0"));
    }

    #[test]
    fn large_ma_message_mentions_exceeds() {
        let rule = AltSvcH3AdvertisementValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "h3=\":443\"; ma=99999999")],
        );
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        )
        .unwrap();
        assert!(v.message.contains("unreasonably large"));
    }

    /// The message is pinned whole: it is assembled from a prefix and the value
    /// it names, and an `is_some` assertion cannot see the two disagree.
    #[test]
    fn a_value_that_is_no_delta_seconds_names_the_production() {
        let rule = AltSvcH3AdvertisementValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "h3=\":443\"; ma=abc")],
        );
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        )
        .unwrap();
        assert_eq!(
            v.message,
            "Alt-Svc h3 entry has 'ma=abc', which is no `delta-seconds`: the production is `1*DIGIT` (RFC 9111 §1.2.2), so a sign, a radix point or any other character leaves the freshness lifetime unstated"
        );
    }

    /// The sign is the finding, and the reason it is one is that the check is
    /// the production rather than an integer type.
    #[test]
    fn a_leading_plus_is_no_delta_seconds() {
        let rule = AltSvcH3AdvertisementValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "h3=\":443\"; ma=+5")],
        );
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        )
        .unwrap();
        assert!(v.message.contains("'ma=+5'"), "{}", v.message);
        assert!(v.message.contains("`1*DIGIT`"), "{}", v.message);
        // `parse::<u64>()` reads this as 5 and would have said nothing.
        assert_eq!("+5".parse::<u64>(), Ok(5));
    }

    /// A run of digits too long for 64 bits is a conforming `delta-seconds`, so
    /// it is reported for the ceiling it exceeds and not as a malformed value.
    #[test]
    fn an_overlong_digit_run_is_measured_against_the_ceiling() {
        let rule = AltSvcH3AdvertisementValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "h3=\":443\"; ma=99999999999999999999999")],
        );
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        )
        .unwrap();
        assert!(v.message.contains("unreasonably large"), "{}", v.message);
        assert!(!v.message.contains("delta-seconds"), "{}", v.message);
    }

    /// The value arrives through the shared `( token / quoted-string )` reader,
    /// so the DQUOTEs are syntax and a `quoted-pair` is the octet after the
    /// backslash. The strip this replaced took the first and last characters.
    #[test]
    fn a_quoted_ma_is_read_by_the_shared_reader() {
        let rule = AltSvcH3AdvertisementValid;
        for (header, expect_finding) in [
            ("h3=\":443\"; ma=\"864\\00\"", false),
            ("h3=\":443\"; ma=\"0\"", true),
        ] {
            let tx = crate::test_helpers::make_test_transaction_with_response(
                200,
                &[("alt-svc", header)],
            );
            let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
            let v = crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &config,
            );
            assert_eq!(v.is_some(), expect_finding, "{header}: {v:?}");
        }
    }

    #[test]
    fn missing_response_returns_none() {
        let rule = AltSvcH3AdvertisementValid;
        let tx = crate::test_helpers::make_test_transaction();
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_header_values_checks_all() {
        let rule = AltSvcH3AdvertisementValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "h2=\":443\""), ("alt-svc", "h3-29=\":443\"")],
        );
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.is_some());
    }

    #[test]
    fn h2_with_bad_ma_is_not_flagged() {
        let rule = AltSvcH3AdvertisementValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "h2=\":443\"; ma=0")],
        );
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.is_none());
    }

    /// A parameter this rule cannot read is the syntax rule's finding on every
    /// protocol, so it is passed over here rather than reported twice in
    /// different words.
    #[test]
    fn a_parameter_that_derives_from_nothing_is_left_to_its_owner() {
        let rule = AltSvcH3AdvertisementValid;
        for header in [
            "h3=\":443\"; ma=",
            "h3=\":443\"; ma",
            "h3=\":443\"; ma=\"unterminated",
            "h3=\":443\"; ;",
        ] {
            let tx = crate::test_helpers::make_test_transaction_with_response(
                200,
                &[("alt-svc", header)],
            );
            let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
            let v = crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &config,
            );
            assert!(v.is_none(), "{header}: {v:?}");
        }
    }

    /// The value is read one `char` per octet. The `to_str()` + `continue` this
    /// replaced dropped the whole field line for an octet at or above %x80 —
    /// the one octet class no `token` admits, so the clearest defect was the one
    /// the rule could not see.
    #[test]
    fn an_obs_text_octet_no_longer_hides_the_line() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = AltSvcH3AdvertisementValid;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        // `h3-29=":443"; ma=<%xFF>` — a draft token, in a value the old reader
        // refused to look at.
        let bad = HeaderValue::from_bytes(b"h3-29=\":443\"; ma=\xff")
            .expect("should construct an obs-text header");
        hm.insert("alt-svc", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: None,
            trailers: None,
        });

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("the draft token is reported");
        assert!(v.message.contains("h3-29"), "{}", v.message);
        Ok(())
    }

    #[test]
    fn syntax_errors_are_skipped() {
        let rule = AltSvcH3AdvertisementValid;
        // Missing '=' - syntax rule handles this, our rule should skip
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "h3example.com:443")],
        );
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.is_none());
    }

    #[test]
    fn empty_protocol_is_skipped() {
        let rule = AltSvcH3AdvertisementValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "=\":443\"")],
        );
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "alt_svc_h3_advertisement_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_server() {
        let rule = AltSvcH3AdvertisementValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    /// Nothing runs a rule's own `examples()` through the engine, so a
    /// `Compliant` value the rule rejects is published as guidance. The four
    /// snippets this replaced carried `#` comments after the field value and
    /// could not have been run at all.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::Compliance;
        let rule = AltSvcH3AdvertisementValid;
        let mut saw_a_finding = false;
        for ex in rule.examples() {
            let fields: Vec<&str> = ex
                .snippet
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    l.strip_prefix("Alt-Svc: ")
                        .unwrap_or_else(|| panic!("not an Alt-Svc line: {l:?}"))
                })
                .collect();
            let pairs: Vec<(&str, &str)> = fields.iter().map(|v| ("alt-svc", *v)).collect();
            let tx = crate::test_helpers::make_test_transaction_with_response(200, &pairs);
            let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
            let found = crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &config,
            );
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule reports its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    found.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    saw_a_finding = true;
                }
            }
        }
        assert!(saw_a_finding, "no published example produced a finding");
    }
}
