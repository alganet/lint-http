// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{combined_field_value_as_written, trim_ows};
use crate::helpers::list::{
    list_members_as_written, quoting_is_balanced, split_semicolons_respecting_quotes,
};
use crate::helpers::shown::shown_in_finding;
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::alpn::{ALPN_PROTOCOL_NAME_OBSOLETE, RFC_9114_3_1_1};
use crate::violations::ViolationDef;

/// Alt-Svc advertising HTTP/3 must name the shipped `h3` ALPN token rather than
/// a draft one (RFC 9114 § 3.1.1).
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

/// The ALPN protocol name HTTP/3 shipped under, spelled as § 3.1.1 spells it.
///
/// **Compared byte-exactly, where the draft scan below folds case**, and the
/// two are not inconsistent: the fold there only ever *widens* what is
/// reported, which is what makes it recordable as a leniency, and a fold here
/// would only ever narrow it. To a client doing § 3's *"simple string
/// comparison"* `H3` is not `h3`, so a field spelling the final token that way
/// has advertised no endpoint that a draft alternative beside it stands in
/// for, and the draft is still the only HTTP/3 on offer.
// cite(RFC 7838 § 3): "With these constraints, recipients can apply simple string comparison to match protocol identifiers."
const FINAL_H3: &str = "h3";

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_7838_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 7838",
    section: Some("3"),
    url: "https://www.rfc-editor.org/rfc/rfc7838.html#section-3",
    note: "Alt-Svc — the field's grammar, the `parameter` production, and the requirement that a recipient ignore a parameter name it does not know",
};

/// The one thing this rule reports, and it is neither the field's nor a
/// parameter's.
///
/// What is wrong with `h3-29` is the ALPN protocol *name* it decodes to, which
/// is the same name whether an `Alt-Svc`, an ALTSVC frame or a ClientHello
/// carried it — so it reports through [`alpn`](crate::violations::alpn), beside
/// the two other ways a name identifies nothing anyone will answer to.
///
/// **The `ma` parameter left this rule.** RFC 7838 § 3.1 defines that lifetime
/// for an `alt-value`, not for an HTTP/3 one, so reading it behind the `h3`
/// gate made the same value a finding under one ALPN name and silence under
/// every other. `alt_svc_header_syntax` reads it now, on every alternative,
/// beside the `persist` that shares its subsection.
static DECLARED: &[&ViolationDef] = &[&ALPN_PROTOCOL_NAME_OBSOLETE];
impl RuleMeta for AltSvcH3AdvertisementValid {
    fn id(&self) -> &'static str {
        "alt_svc_h3_advertisement_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Alt-Svc H3 Advertisement Valid")
    }

    fn description(&self) -> &'static str {
        "Reads the `Alt-Svc` response header field and asks one thing of it: that an HTTP/3 endpoint is advertised under a name a current client answers to.\n\nRFC 9114 §3.1.1: *\"An HTTP origin can advertise the availability of an equivalent HTTP/3 endpoint via the Alt-Svc HTTP response header field or the HTTP/2 ALTSVC frame ([ALTSVC]) using the \"h3\" ALPN token.\"* A draft-era token — `h3-29`, `h3-Q050`, `h3-27` — is a different ALPN protocol name, so a client that speaks HTTP/3 and not that draft finds nothing it can use at the alternative. **It is reported only where the field names no `h3` at all**, because that sentence asks an origin to advertise an equivalent HTTP/3 endpoint using `h3`, and a field carrying `h3` has done so — the draft alternative beside it is one a client that knows only `h3` never looks at. `Alt-Svc: h3=\":443\", h3-29=\":443\"` is the shape almost every draft advertisement on the web is written in and draws nothing; `Alt-Svc: h3-29=\":443\"` is the whole HTTP/3 offer written under a name nothing current negotiates, and draws the finding.\n\n**The `h3` is looked for byte-exactly** where the draft scan folds case, and the asymmetry runs the right way in both places: the fold only widens what is reported, and `H3` is not `h3` to a recipient doing §3\'s *\"simple string comparison\"*, so `H3=\":443\", h3-29=\":443\"` still offers HTTP/3 under the draft name alone.\n\n**Everything else about the field is `alt_svc_header_syntax`\'s**, on every protocol rather than on `h3` alone: the shape of a member and of a parameter, and — since the lifetime RFC 7838 §3.1 defines belongs to an `alt-value` and not to an HTTP/3 one — the `ma` parameter, which this rule used to read behind the `h3` gate and no longer does. Whether the ALPN name is registered is `alt_svc_protocol_registered`\'s.\n\nThe field lines are joined before they are read (RFC 9110 §5.3), because `1#alt-value` is the list that licenses the join, and the value is read one `char` per octet so that an `obs-text` octet is measured rather than hiding the line it is written on."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9114_3_1_1, RFC_7838_3]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("The shipped ALPN token"),
                snippet: "Alt-Svc: h3=\":443\"; ma=2592000",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("An `h3` entry beside another protocol's"),
                snippet: "Alt-Svc: h2=\":443\", h3=\":443\"; ma=3600",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("A draft token beside the final one: the client takes `h3`"),
                snippet: "Alt-Svc: h3=\":443\"; ma=86400, h3-29=\":443\"; ma=86400",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("A draft protocol identifier, and the whole HTTP/3 offer"),
                snippet: "Alt-Svc: h3-29=\":443\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Two draft tokens, and no final one beside them"),
                snippet: "Alt-Svc: h3-29=\":443\", h3-27=\":443\"",
            },
        ]
    }
}

impl Rule for AltSvcH3AdvertisementValid {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // The body sits behind an Option so `?` can end it early on a message
        // with nothing to read; what it ends with is every finding the field
        // earned, which is not always one.
        //
        // **Each draft token in the field is named, and the `ma` findings keep
        // their at-most-one shape.** A `protocol-id` names one alternative
        // service, so a field advertising two draft tokens has advertised two
        // endpoints no client can negotiate, and reporting the first alone said
        // the second was fine. An `ma` value is a property of an advertisement
        // this rule has already accepted as `h3`, and its repair is the same
        // wherever it recurs, so the first is the finding and the rest would be
        // the same sentence again. Neither kind can mask the other now: the
        // stop that used to end the read on either has become a flag on one.
        let finding = || -> Option<Vec<Violation>> {
            let resp = tx.response.as_ref()?;
            let mut out: Vec<Violation> = Vec::new();

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

            // Asked once for the whole field, because it is a fact about the
            // field: a draft token is reported for what the alternatives
            // *beside* it do not say, and each member cannot see the others.
            let final_h3_advertised = advertises_final_h3(value);

            for member in list_members_as_written(value) {
                // An empty list element and a member with no '=' are both
                // `alt_svc_header_syntax`'s findings; this rule has no
                // alternative to read in either.
                if member.is_empty() {
                    continue;
                }
                let parts = split_semicolons_respecting_quotes(member);
                let (alternative, _parameters) = parts
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

                // Draft h3 protocol IDs (h3-29, h3-Q050, etc.): the ALPN token
                // HTTP/3 shipped under is "h3", so an "h3-*" draft token names a
                // protocol nothing current negotiates.
                //
                // **Reported only where the field names no `h3` at all.** The
                // sentence cited asks that an equivalent HTTP/3 endpoint be
                // advertised using `h3`, and a field carrying `h3` has done so;
                // the draft alternative beside it is one a client that knows only
                // `h3` never looks at. Where it stands alone the whole HTTP/3
                // offer is a name no current client answers to, which is the
                // finding. A draft token is still not an `h3` entry either way,
                // so the `ma` reading below does not run on one.
                // cite(RFC 9114 § 3.1.1): "An HTTP origin can advertise the availability of an equivalent HTTP/3 endpoint via the Alt-Svc HTTP response header field or the HTTP/2 ALTSVC frame ([ALTSVC]) using the "h3" ALPN token."
                if proto_lower.starts_with("h3-") {
                    if !final_h3_advertised {
                        out.push(ctx.report_with(
                            &ALPN_PROTOCOL_NAME_OBSOLETE,
                            format!(
                                "Alt-Svc advertises HTTP/3 only under the draft protocol identifier '{}'; no alternative in this field names the final 'h3' token, so a client that does not implement that draft is offered no HTTP/3 endpoint",
                                shown_in_finding(protocol_id)
                            ),
                        ));
                    }
                    continue;
                }
            }

            Some(out)
        };
        finding().unwrap_or_default()
    }
}

/// Whether any alternative in this field advertises HTTP/3 under the token it
/// shipped with.
///
/// **The question a draft token raises is about the field, not about the
/// name.** RFC 9114 § 3.1.1 asks that an origin advertising an equivalent
/// HTTP/3 endpoint do so using `h3`; an origin that lists `h3` has done that,
/// and a draft token beside it is a second alternative offered to whatever
/// still speaks that draft. A client that does not simply picks the one it
/// knows. So the draft name is a defect only where it is the *whole* HTTP/3
/// offer — there the field advertises an endpoint no current client can
/// negotiate, which is the harm the entry names.
///
/// The `protocol-id` is read as written, the same spelling the draft scan
/// reads, so both halves of one question are asked of one form. An `h3`
/// escaped as `%68%33` is not counted here and does not need to be: this field
/// constrains a name to one spelling, and encoding an octet a `token` already
/// admits is `alt_svc_header_syntax`'s finding rather than a second way to
/// name the shipped protocol.
///
/// `members` are the field's `alt-value`s, already split on the commas a
/// `quoted-string` does not swallow.
// cite(RFC 9114 § 3.1.1): "An HTTP origin can advertise the availability of an equivalent HTTP/3 endpoint via the Alt-Svc HTTP response header field or the HTTP/2 ALTSVC frame ([ALTSVC]) using the "h3" ALPN token."
fn advertises_final_h3(value: &str) -> bool {
    list_members_as_written(value).into_iter().any(|member| {
        let parts = split_semicolons_respecting_quotes(member);
        let Some((alternative, _)) = parts.split_first() else {
            return false;
        };
        alternative
            .split_once('=')
            .is_some_and(|(protocol_id, _)| protocol_id == FINAL_H3)
    })
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &AltSvcH3AdvertisementValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    // Nothing to read, or an HTTP/3 endpoint under the name it shipped with.
    #[case(None, false)]
    #[case(Some("h3=\":443\"; ma=2592000"), false)]
    #[case(Some("h3=\":443\""), false)]
    #[case(Some("h3=example.com:443; ma=86400"), false)]
    #[case(Some("h2=\":443\", h3=\":443\"; ma=3600"), false)]
    #[case(Some("h2=\":443\""), false)]
    #[case(Some("clear"), false)]
    // Draft version violations
    #[case(Some("h3-29=\":443\""), true)]
    #[case(Some("h3-Q050=\":443\""), true)]
    #[case(Some("h3-27=\":443\"; ma=3600"), true)]
    #[case(Some("h2=\":443\", h3-29=\":443\""), true)]
    // The protocol-id fold, which widens: a case-variant draft token is still
    // named. A case-variant `h3` is not the shipped token to a recipient doing
    // §3's simple string comparison, so it stands in for nothing.
    #[case(Some("H3=\":443\"; ma=86400"), false)]
    // Every way an `ma` can fail to state a lifetime is `alt_svc_header_syntax`'s
    // finding now, on every alternative rather than on `h3` alone. None of them
    // is this rule's, and a draft token is the only thing it still answers for.
    #[case(Some("h3=\":443\"; ma=0"), false)]
    #[case(Some("h3=\":443\"; ma=99999999"), false)]
    #[case(Some("h3=\":443\"; ma=+5"), false)]
    #[case(Some("h3=\":443\"; ma=\"\""), false)]
    #[case(Some("h3=\":443\"; ma="), false)]
    #[case(Some("h3=\":443\"; ma = 0"), false)]
    // Persist param without ma (valid, defaults to 24h)
    #[case(Some("h3=\":443\"; persist=1"), false)]
    // Multiple params including valid ma
    #[case(Some("h3=\":443\"; persist=1; ma=86400"), false)]
    // CLEAR directive (case-insensitive)
    #[case(Some("CLEAR"), false)]
    // Draft with numeric suffix only
    #[case(Some("h3-14=\":443\""), true)]
    // The same draft token beside the one HTTP/3 shipped under: the field has
    // advertised the shipped protocol, so nothing is offered under a name
    // alone.
    #[case(Some("h3=\":443\", h3-14=\":443\""), false)]
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

        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "alt_svc_h3_advertisement_valid",
        ]);

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

    /// Every draft token in the field is a separate advertisement, and each one
    /// is named. The rule used to end its read on the first finding, so a field
    /// carrying two draft tokens reported the first and said nothing about the
    /// second — which is the shape most of them are actually written in, `h3-29`
    /// beside a second draft the same deployment still offers.
    #[test]
    fn every_draft_token_in_the_field_is_named() {
        let rule = AltSvcH3AdvertisementValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("alt-svc", "h3-29=\":443\", h3-27=\":443\"")],
        );
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert_eq!(v.len(), 2, "{:?}", v);
        assert!(v
            .iter()
            .all(|f| f.violation == ALPN_PROTOCOL_NAME_OBSOLETE.id));
        assert!(v[0].message.contains("h3-29"), "{}", v[0].message);
        assert!(v[1].message.contains("h3-27"), "{}", v[1].message);
    }

    /// The shape almost every draft advertisement on the web is written in:
    /// the draft token beside the token HTTP/3 shipped under. Nothing is
    /// reported, because nothing is wrong with it — a client that implements
    /// the draft may take that alternative and one that does not takes `h3`,
    /// and the sentence asking an origin to advertise HTTP/3 using `h3` has
    /// been answered by the field itself.
    ///
    /// This drew a finding on every such field, whose message told the sender
    /// to use the final token instead — advice the field had already taken.
    #[rstest]
    #[case("h3=\":443\"; ma=86400, h3-29=\":443\"; ma=86400")]
    #[case("h3-29=\":443\", h3=\":443\"")]
    #[case("h3=\":443\"; ma=3600, h3-25=\":443\"; ma=3600, h3-29=\":443\"; ma=3600")]
    #[case("h2=\":443\", h3=\":443\", h3-27=\":443\"")]
    fn a_draft_token_beside_the_final_one_is_no_finding(#[case] header: &str) {
        let rule = AltSvcH3AdvertisementValid;
        let tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("alt-svc", header)]);
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.is_empty(), "unexpected finding for {header:?}: {v:?}");
    }

    /// What counts as having advertised the shipped protocol is asked
    /// byte-exactly, where the draft scan folds case — and the two are not in
    /// tension. The fold widens what this rule reports and is recordable as a
    /// leniency for exactly that reason; folding here would narrow it, and
    /// would do so by claiming a recipient reads `H3` as `h3`, which §3 says it
    /// does not. So a field spelling the final token in the wrong case has
    /// advertised no endpoint the draft one stands in for, and the draft is
    /// still the only HTTP/3 on offer.
    #[rstest]
    #[case("H3=\":443\", h3-29=\":443\"")]
    #[case("h3-29=\":443\", H3=\":443\"")]
    fn a_case_variant_final_token_does_not_stand_in_for_h3(#[case] header: &str) {
        let rule = AltSvcH3AdvertisementValid;
        let tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("alt-svc", header)]);
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].violation, ALPN_PROTOCOL_NAME_OBSOLETE.id);
        assert!(v[0].message.contains("h3-29"), "{}", v[0].message);
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
        // The subject is the ALPN name and not this field: the same name would
        // be the same defect in an ALTSVC frame or a ClientHello.
        assert_eq!(v.violation, "alpn_protocol_name_obsolete");
        assert_eq!(v.severity, crate::lint::Severity::Warn);
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
            body_interrupted: false,
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
    fn needs_a_response() {
        let rule = AltSvcH3AdvertisementValid;
        assert!(rule.needs_response());
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
