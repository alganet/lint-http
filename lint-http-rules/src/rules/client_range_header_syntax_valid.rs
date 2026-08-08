// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientRangeHeaderSyntaxValid;

impl Rule for ClientRangeHeaderSyntaxValid {
    fn id(&self) -> &'static str {
        "client_range_header_syntax_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        use hyper::header::RANGE;

        let hdrs = tx.request.headers.get_all(RANGE);
        hdrs.iter().next()?;

        // `to_str` refuses every octet outside visible US-ASCII, and the shared
        // reader below folds that refusal into the same `None` it returns for an
        // absent field. This rule owns the difference -- one of the two is a
        // finding about the message on the wire -- so the question the helper does
        // not report on is asked here, before it is asked to read anything.
        //
        // The message used to call such a value "non-UTF8", which was wrong twice:
        // `to_str` rejects a perfectly good UTF-8 `é` as readily as a lone 0xFF,
        // and neither is the reason it is a finding. The reason is that no part of
        // a ranges-specifier -- a token, `=`, or a range-spec -- is built from
        // anything but visible US-ASCII.
        for hv in hdrs.iter() {
            if hv.to_str().is_err() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Range header holds an octet no part of a ranges-specifier admits"
                        .into(),
                });
            }
        }

        // Two field lines with one name are one field value: a recipient appends
        // them in order, separated by comma SP. Reading them as two values answers
        // about a value nobody sees -- `bytes=0-1` beside `bytes=2-3` is a single
        // range-set whose second element is `bytes=2-3`, which is a specifier the
        // `bytes` unit has no form for, and it is that value the origin acts on.
        //
        // Whether the sender was permitted to send two lines at all is a separate
        // and arguable question -- § 5.3's exception turns on whether the field's
        // definition allows a comma-separated list, and `Range`'s does, one level
        // down, in `range-set`. Joining decides nothing about it and needs to
        // decide nothing: the joined value is measured against the same grammar
        // either way. Every line was read cleanly just above, so the helper's
        // remaining `None` is the absent case, which the first line here ruled out.
        let value = crate::helpers::headers::get_all_header_values(&tx.request.headers, "range")?;

        // cite(RFC 9110 § 14.2): "The "Range" header field on a GET request modifies the method semantics to request transfer of only one or more subranges"
        // The split is the shared one, not a second copy of it: the unit is a
        // token, so the first `=` is the separator whatever follows it, and the
        // same function answers this question for `Content-Range`.
        let Some((unit, range_set)) = crate::helpers::content_range::split_ranges_specifier(&value)
        else {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Invalid Range header '{}': not a ranges-specifier (a range-unit token, '=', then a range-set)",
                    value
                ),
            });
        };

        if let Err(e) = validate_range_set(&unit, range_set) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!("Invalid Range header '{}': {}", value, e),
            });
        }
        None
    }

    fn description(&self) -> &'static str {
        "Checks that the `Range` request header, when present, follows the `byte-range-set` syntax defined by RFC 9110. This rule validates the unit (e.g., `bytes=`) and that each range specifier is syntactically well-formed (numeric byte positions, suffix forms like `-500`, open-ended forms like `9500-`, and correct ordering `first <= last`)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 9110",
            section: Some("14.1.2"),
            url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1.2",
            note: "Range header syntax",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /big-file HTTP/1.1\nHost: example.com\nRange: bytes=0-499\n\nGET /big-file HTTP/1.1\nHost: example.com\nRange: bytes=500-999,1000-1499\n\nGET /big-file HTTP/1.1\nHost: example.com\nRange: bytes=-500\n\nGET /big-file HTTP/1.1\nHost: example.com\nRange: bytes=9500-",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a range unit this rule does not model)"),
                snippet: "GET /catalogue HTTP/1.1\nHost: example.com\nRange: items=0-1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /big-file HTTP/1.1\nHost: example.com\nRange: bytes=abc\n\nGET /big-file HTTP/1.1\nHost: example.com\nRange: bytes=5-3",
            },
        ]
    }
}

/// Walk a range-set, checking first what holds for every range unit and then, if
/// the unit is one whose specifiers this rule knows, what holds for that unit.
///
/// The two halves used to be one: the rule accepted `bytes` and reported every
/// other unit as an unsupported one, so `Range: items=0-1` -- a conforming
/// request to a resource that partitions itself into items -- was published as
/// this rule's own example of bad syntax. Range units are an open registry and
/// the specifier grammar is deliberately generic; what an `items` range-spec may
/// hold is defined by whoever defined `items`, and nothing on the wire tells this
/// rule. A recipient that does not know the unit is told to *ignore* the field,
/// not to treat it as malformed.
///
/// What survives for an unknown unit is what the generic grammar says: the
/// field's list structure, and that each range-spec is drawn from `other-range`'s
/// octets -- which every alternative of `range-spec` is, so a space inside a
/// specifier is outside the grammar for `bytes` and `items` alike.
fn validate_range_set(unit: &str, range_set: &str) -> Result<(), String> {
    if range_set.is_empty() {
        return Err("no range-spec found".into());
    }

    for spec in range_set.split(',') {
        // The list construct puts OWS on either side of each comma, and OWS is
        // SP / HTAB. `trim` reaches further than that in general and no further
        // than that here: `to_str` has already refused every octet outside
        // visible US-ASCII, of which SP and HTAB are the only whitespace.
        let spec = spec.trim();
        if spec.is_empty() {
            return Err("empty range-spec".into());
        }

        // Not `parse_list_header`, which drops empty elements: that is the right
        // reading for the seventy-odd recipients that call it and the wrong one
        // here, because the empty element is this rule's evidence. By the time
        // that function answers, what a sender must not have generated is gone.
        if let Some(c) = spec.chars().find(|c| !c.is_ascii_graphic()) {
            return Err(format!(
                "range-spec '{}' holds {:?}, which no range-spec admits",
                spec, c
            ));
        }

        if unit == "bytes" {
            validate_bytes_range_spec(spec)?;
        }
    }
    Ok(())
}

/// Check one range-spec against the two forms the `bytes` unit defines.
fn validate_bytes_range_spec(spec: &str) -> Result<(), String> {
    // Suffix form: -<suffix-length>
    if let Some(num) = spec.strip_prefix('-') {
        if num.is_empty() {
            return Err("invalid suffix-byte-range (missing digits)".into());
        }
        if !num.chars().all(|c| c.is_ascii_digit()) {
            return Err("suffix-byte-range contains non-digit".into());
        }
        return Ok(());
    }

    // Otherwise expect <first>-<last?> where last may be empty
    let dash_idx = spec
        .find('-')
        .ok_or_else(|| "byte-range-spec missing '-'".to_string())?;
    let first = spec[..dash_idx].trim();
    let last = spec[dash_idx + 1..].trim();

    if first.is_empty() {
        return Err("byte-range-spec missing first position".into());
    }
    if !first.chars().all(|c| c.is_ascii_digit()) {
        return Err("first byte-pos contains non-digit".into());
    }

    if !last.is_empty() {
        if !last.chars().all(|c| c.is_ascii_digit()) {
            return Err("last byte-pos contains non-digit".into());
        }
        // check ordering first <= last
        let first_v: u128 = first
            .parse()
            .map_err(|_| "first byte-pos overflow".to_string())?;
        let last_v: u128 = last
            .parse()
            .map_err(|_| "last byte-pos overflow".to_string())?;
        if first_v > last_v {
            return Err("first byte-pos greater than last".into());
        }
    }
    Ok(())
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ClientRangeHeaderSyntaxValid;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_test_transaction;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn judge(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        let rule = ClientRangeHeaderSyntaxValid;
        rule.check_transaction(
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    #[rstest]
    #[case("bytes=0-499", false)]
    #[case("bytes=500-999,1000-1499", false)]
    #[case("bytes=-500", false)]
    #[case("bytes=9500-", false)]
    #[case("bytes=0-0,-1", false)]
    // A range unit whose specifiers this rule does not know: the generic grammar
    // still holds, and nothing beyond it can be asked.
    #[case("items=0-1", false)]
    #[case("items=chapter-3", false)]
    #[case("items=0 1", true)]
    #[case("items=", true)]
    #[case("items=1-2,,3-4", true)]
    // Not a ranges-specifier at all, whatever the unit would have meant.
    #[case("bytes 0-499", true)]
    #[case("by(tes=0-1", true)]
    #[case("=0-1", true)]
    #[case("bytes=abc", true)]
    #[case("bytes=5-3", true)]
    #[case("bytes=", true)]
    #[case("bytes= ,1-2", true)]
    #[case("bytes=-", true)]
    #[case("bytes=500", true)]
    #[case("bytes=1-2,", true)]
    #[case("bytes=5-a", true)]
    #[case("bytes=a-5", true)]
    #[case(
        "bytes=340282366920938463463374607431768211456-340282366920938463463374607431768211457",
        true
    )]
    fn check_range_cases(
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let mut tx = make_test_transaction();
        tx.request.headers.insert("range", value.parse()?);

        let v = judge(&tx);

        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}', got none", value);
        } else {
            assert!(
                v.is_none(),
                "didn't expect violation for '{}', got some: {:?}",
                value,
                v
            );
        }
        Ok(())
    }

    /// This used to append `bytes=0-1` and `items=0-1` and rest on the second one
    /// being reported for its unit -- so it asserted a defect, not the claim in
    /// its name. Two lines are one value here, and the name says which.
    #[rstest]
    // Joined: `bytes=0-1, bytes=2-3`, whose second element is a specifier the
    // `bytes` unit has no form for. Neither line says that on its own.
    #[case(&["bytes=0-1", "bytes=2-3"], true)]
    #[case(&["bytes=0-1", "bytes=5-3"], true)]
    // Joined: `bytes=0-1, 2-3`, which is one well-formed two-element range-set.
    #[case(&["bytes=0-1", "2-3"], false)]
    fn field_lines_are_joined_before_they_are_parsed(
        #[case] lines: &[&str],
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let mut tx = make_test_transaction();
        for line in lines {
            tx.request
                .headers
                .append("range", line.parse::<HeaderValue>()?);
        }

        assert_eq!(
            judge(&tx).is_some(),
            expect_violation,
            "for the field lines {lines:?}"
        );
        Ok(())
    }

    /// Nothing else runs a rule's published examples through it, so a snippet
    /// that is not a message at all reads as documentation to its author and
    /// publishes as HTTP: three of these blocks used to carry a `# non-numeric`
    /// line where a field line belongs. Every block here is one request, and the
    /// verdict on it has to be the one the label promises.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::Compliance;

        let mut saw_a_finding = false;
        for ex in ClientRangeHeaderSyntaxValid.examples() {
            for block in ex.snippet.split("\n\n") {
                let mut lines = block.lines();
                let request_line = lines.next().expect("a request has a request line");
                assert!(
                    request_line.ends_with(" HTTP/1.1"),
                    "not a request line: {request_line:?}"
                );

                let mut tx = make_test_transaction();
                tx.request.headers.clear();
                for line in lines {
                    let (name, value) = line
                        .split_once(": ")
                        .unwrap_or_else(|| panic!("not a field line: {line:?}"));
                    tx.request.headers.append(
                        hyper::header::HeaderName::from_bytes(name.as_bytes())
                            .unwrap_or_else(|_| panic!("not a field name: {name:?}")),
                        value
                            .parse::<HeaderValue>()
                            .unwrap_or_else(|_| panic!("not a field value: {value:?}")),
                    );
                }

                let found = judge(&tx);
                match ex.compliance {
                    Compliance::Compliant => assert!(
                        found.is_none(),
                        "rule reports its Compliant example {block:?}: {found:?}"
                    ),
                    Compliance::NonCompliant => {
                        assert!(
                            found.is_some(),
                            "rule accepts its NonCompliant example {block:?}"
                        );
                        saw_a_finding = true;
                    }
                }
            }
        }
        assert!(saw_a_finding, "the guard ran without exercising a finding");
    }

    #[test]
    fn header_absent_no_violation() -> anyhow::Result<()> {
        let tx = make_test_transaction();
        let v = judge(&tx);
        assert!(v.is_none());
        Ok(())
    }

    /// `0xFF` is not UTF-8 and `0xC3 0xA9` is -- the `é` a client might put in a
    /// field value by accident. Both are outside every production this field is
    /// built from, and neither is readable, so the finding is the same one.
    #[rstest]
    #[case(&[0xff])]
    #[case("bytes=0-\u{e9}".as_bytes())]
    fn an_octet_outside_the_grammar_is_reported(#[case] bad: &[u8]) -> anyhow::Result<()> {
        let mut tx = make_test_transaction();
        let bad = HeaderValue::from_bytes(bad).expect("should construct the header value");
        tx.request.headers.insert("range", bad);

        let v = judge(&tx);
        let msg = v.expect("expected a violation").message;
        assert!(
            msg.contains("no part of a ranges-specifier admits"),
            "reported for another reason: {msg}"
        );
        Ok(())
    }

    #[test]
    fn scope_is_client() {
        let rule = ClientRangeHeaderSyntaxValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
