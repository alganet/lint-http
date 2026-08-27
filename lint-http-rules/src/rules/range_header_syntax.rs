// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct RangeHeaderSyntax;

impl Rule for RangeHeaderSyntax {
    fn id(&self) -> &'static str {
        "range_header_syntax"
    }

    /// `Range` is defined on a request and nothing defines it on a response, so
    /// the enum records what the field is rather than filtering anything: in this
    /// engine only `Server` narrows a dispatch, and this rule reads
    /// `tx.request.headers` in any case.
    ///
    // cite(RFC 9110 § 14.2): "The "Range" header field on a GET request modifies the method semantics to request transfer of only one or more subranges of the selected representation data (Section 8.1), rather than the entire selected representation."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
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
            use hyper::header::RANGE;

            // A request that names no range is every other request. The absence is
            // not a finding and not an oversight either -- the whole feature is
            // optional, and a recipient is meant to be able to ignore it.
            //
            // cite(RFC 9110 § 14): "Range requests are an OPTIONAL feature of HTTP, designed so that recipients not implementing this feature (or not supporting it for the target resource) can respond as if it is a normal GET request without impacting interoperability."
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
            //
            // cite(RFC 9110 § 5.6.2): "Delimiters are chosen from the set of US-ASCII visual characters not allowed in a token (DQUOTE and "(),/:;<=>?@[\]{}")."
            // cite(RFC 9110 § 14.1.1, label: other-range grammar): "other-range   = 1*( %x21-2B / %x2D-7E )"
            for hv in hdrs.iter() {
                if hv.to_str().is_err() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: ctx.severity,
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
            //
            // cite(RFC 9110 § 5.3): "A recipient MAY combine multiple field lines within a field section that have the same field name into one field line, without changing the semantics of the message, by appending each subsequent field line value to the initial field line value in order, separated by a comma (",") and optional whitespace (OWS, defined in Section 5.6.3).  For consistency, use comma SP."
            let value = crate::helpers::headers::get_all_header_values(
                &tx.request.headers,
                RANGE.as_str(),
            )?;

            // The split is the shared one, not a second copy of it: the unit is a
            // token, so the first `=` is the separator whatever follows it, and the
            // same function answers this question for `Content-Range`.
            //
            // cite(RFC 9110 § 14.2, label: Range grammar): "Range = ranges-specifier"
            // cite(RFC 9110 § 14.1.1, label: ranges-specifier grammar): "ranges-specifier = range-unit "=" range-set"
            let Some((unit, range_set)) =
                crate::helpers::content_range::split_ranges_specifier(&value)
            else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: ctx.severity,
                    message: format!(
                        "Invalid Range header '{}': not a ranges-specifier (a range-unit token, '=', then a range-set)",
                        value
                    ),
                });
            };

            // The one sentence that makes any of the checks below mean something. It
            // is also what bounds them: invalidity is decided per range-unit, and this
            // rule knows one range-unit.
            //
            // cite(RFC 9110 § 14.1.1): "A ranges-specifier is invalid if it contains any range-spec that is invalid or undefined for the indicated range-unit."
            if let Err(e) = validate_range_set(&unit, range_set) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: ctx.severity,
                    message: format!("Invalid Range header '{}': {}", value, e),
                });
            }

            // Three things a well-formed ranges-specifier can still be, none of them
            // reported here, all of them named so the silence is not read as an
            // oversight.
            //
            // *Unsatisfiable* is not *invalid*: the sentence below asks after a valid
            // range-spec, and the answer turns on the length of the selected
            // representation, which no request carries.
            //
            // *On a method other than GET* is a requirement on the server, which must
            // ignore such a field. Nothing there is addressed to the client that sent
            // it, so the rule has nothing to measure the request against.
            //
            // *Descending or overlapping* is a SHOULD with an escape clause about a
            // client's own needs -- "unless there is a specific need to request a
            // later part earlier" -- and a request records the ranges, not the need.
            //
            // cite(RFC 9110 § 14.1.2): "For a GET request, a valid bytes range-spec is satisfiable if it is either:"
            // cite(RFC 9110 § 14.2): "A server MUST ignore a Range header field received with a request method that is unrecognized or for which range handling is not defined.  For this specification, GET is the only method for which range handling is defined."
            // cite(RFC 9110 § 14.2): "A client that is requesting multiple ranges SHOULD list those ranges in ascending order (the order in which they would typically be received in a complete representation) unless there is a specific need to request a later part earlier."
            None
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Checks that a `Range` request header field is a well-formed `ranges-specifier`: a range-unit token, an `=`, and a non-empty comma-separated list of range specifiers.\n\n**The unit decides how much can be checked.** RFC 9110 §14.1.1 says the specifier grammar is generic on purpose — \"each range unit is expected to specify requirements on when int-range, suffix-range, and other-range are allowed\" — and range unit names are an open IANA registry. So for a unit other than `bytes` this rule checks only what holds whatever the unit: that the list has at least one element, that no element is empty (§5.6.1.1 makes an empty list element a sender's MUST NOT), and that each element is one run of visible non-comma characters, which every alternative of `range-spec` is. `Range: items=0-1` is not reported. What an `items` specifier may hold is defined by whoever defined `items`, and an origin server that does not understand a unit is told by §14.2 to ignore the field, not to treat it as malformed.\n\n**For `bytes` it also checks the two forms that unit defines**: `first-pos \"-\" [ last-pos ]` and `\"-\" suffix-length`, every position `1*DIGIT`, the last position not below the first, and no third form — §14.1.2 says \"Byte ranges do not use the other-range specifier\". Positions are compared as decimal numerals rather than parsed into an integer, because the same section requires recipients to \"anticipate potentially large decimal numerals\" without failing on overflow.\n\n**All of the field's lines are joined before parsing**, in order and separated by comma SP, because that is the value a recipient acts on: `bytes=0-1` on one line and `bytes=2-3` on the next make one range-set whose second element no byte range specifier admits.\n\n**What it does not report.** Whether a range is *satisfiable* — that depends on the length of the selected representation, which no request carries. A `Range` on a method other than GET — the requirement there is on the server, which must ignore such a field; nothing addresses the client that sent it. Overlapping or descending ranges — §14.2 asks for ascending order with a SHOULD that ends \"unless there is a specific need to request a later part earlier\", and a request records the ranges rather than the need.\n\n**What a finding costs.** §14.2 lets a server that supports range requests \"ignore or reject\" a field carrying an invalid ranges-specifier, so the price of one is the range request rather than the request — a client that asked for part of a representation is answered with all of it."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("14.1.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1.1",
                note: "Range Specifiers: `ranges-specifier = range-unit \"=\" range-set`, and the grammar under it is generic — each range unit says which of `int-range`, `suffix-range` and `other-range` its specifiers may use. A ranges-specifier is invalid when it holds a range-spec \"that is invalid or undefined for the indicated range-unit\", which is the sentence every check here rests on and the one that bounds them to the unit the rule knows",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("14.1.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1.2",
                note: "Byte Ranges: the two forms the `bytes` unit defines, both `1*DIGIT`, with `other-range` withdrawn for this unit. It also requires recipients to anticipate potentially large decimal numerals and prevent parsing errors due to integer conversion overflows — so positions are compared as digits and no ceiling is imposed — and it defines satisfiability, which is a question about the representation and not about the field",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("14.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.2",
                note: "`Range`: the field is a `ranges-specifier` on a GET request. A server MUST ignore one received with a method for which range handling is not defined, an origin server MUST ignore one whose range unit it does not understand, and a server that supports range requests MAY ignore or reject an invalid one — which is what a finding here costs. The ascending-order requirement is a SHOULD carrying an exception about the client's own needs, which a request does not record",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("14.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1",
                note: "Range Units: `range-unit = token`, case-insensitive, an open registry, \"intended to be extensible\" — which is why a unit other than `bytes` is not a finding",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.1.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1",
                note: "Sender Requirements for the list construct: OWS on either side of each comma, and a sender MUST NOT generate empty list elements. Recipients are told the opposite in §5.6.1.2 — parse and ignore them — so the shared list reader, which drops them, cannot answer this rule's question",
            },
        ]
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
///
/// One leniency arrives from the shared split, which trims the range-set: a
/// space after the `=` is accepted, and `1#range-spec` does not generate one.
/// The specification's own example of a valid bytes range specifier has it --
/// `bytes= 0-999, 4500-5499, -1000` -- so the document disagrees with its list
/// production, and following the example is the reading that reports nobody for
/// writing down what the section printed.
///
// cite(RFC 9110 § 14.1): "All range unit names are case-insensitive and ought to be registered within the "HTTP Range Unit Registry", as defined in Section 16.5.1."
// cite(RFC 9110 § 14.1): "Range units are intended to be extensible, as described in Section 16.5."
// cite(RFC 9110 § 14.1.1): "The range unit name determines what kinds of range-spec are applicable to its own specifiers.  Hence, the following grammar is generic: each range unit is expected to specify requirements on when int-range, suffix-range, and other-range are allowed."
// cite(RFC 9110 § 14.2): "An origin server MUST ignore a Range header field that contains a range unit it does not understand.  A proxy MAY discard a Range header field that contains a range unit it does not understand."
// cite(RFC 9110 § 14.1.2, label: a bytes range-set the section prints with a leading space): "bytes= 0-999, 4500-5499, -1000"
fn validate_range_set(unit: &str, range_set: &str) -> Result<(), String> {
    // The `1` in `1#` -- a range-set with no element in it is not a range-set.
    // cite(RFC 9110 § 14.1.1, label: range-set grammar): "range-set        = 1#range-spec"
    if range_set.is_empty() {
        return Err("no range-spec found".into());
    }

    for spec in range_set.split(',') {
        // The list construct puts OWS on either side of each comma, and OWS is
        // SP / HTAB. `trim` reaches further than that in general and no further
        // than that here: `to_str` has already refused every octet outside
        // visible US-ASCII, of which SP and HTAB are the only whitespace.
        //
        // cite(RFC 9110 § 5.6.1.1): "1#element => element *( OWS "," OWS element )"
        // cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
        let spec = spec.trim();

        // Not `list_members`, which drops empty elements: that is the right
        // reading for the recipients that call it and the wrong one here, because
        // the empty element is this rule's evidence. By the time that function
        // answers, what a sender must not have generated is gone.
        //
        // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
        if spec.is_empty() {
            return Err("empty range-spec".into());
        }

        // What is left to say about a unit this rule does not model. Every
        // alternative of `range-spec` fits inside `other-range`'s octets -- the
        // int-range and suffix-range forms are digits and a hyphen -- so a space
        // or a control character inside a specifier is outside all three.
        //
        // `is_ascii_graphic` is `%x21-7E`, one octet wider than the production:
        // it admits the comma at `%x2C`. That is exact here and only here,
        // because the split above consumed every comma in the range-set, so the
        // difference between the two sets cannot reach this predicate. Anything
        // reading a range-spec it did not split for itself needs the narrower one.
        //
        // cite(RFC 9110 § 14.1.1, label: other-range grammar): "other-range   = 1*( %x21-2B / %x2D-7E )"
        if let Some(c) = spec.chars().find(|c| !c.is_ascii_graphic()) {
            return Err(format!(
                "range-spec '{}' holds {:?}, which no range-spec admits",
                spec, c
            ));
        }

        // The one unit whose specifiers this rule can go on to read. The name is
        // compared against a lowercase literal because the shared split has
        // already folded it, which is the sentence above about case.
        //
        // cite(RFC 9110 § 14.1.2): "The "bytes" range unit is used to express subranges of a representation data's octet sequence."
        if unit == "bytes" {
            validate_bytes_range_spec(spec)?;
        }
    }
    Ok(())
}

/// Check one range-spec against the two forms the `bytes` unit defines.
///
/// Both forms are digits and one hyphen, so the whole of the check is which side
/// of the hyphen the digits are on and how many of them there are. Neither
/// production leaves room for whitespace between the two -- there is nothing
/// between `first-pos` and `"-"` to put it in. Two `trim` calls used to sit on
/// either side of the hyphen and spend that room anyway, so `bytes=0 - 499`
/// passed: a value no sender may generate, accepted by the only rule that reads
/// this field. They are gone rather than tightened, because a range-spec's
/// octets are settled before this function is reached.
///
/// A specifier that is neither form is not an `other-range` fallback here: for
/// this unit and no other, the specification withdraws that alternative outright.
///
// cite(RFC 9110 § 14.1.2): "Each byte range is expressed as an integer range at some offset, relative to either the beginning (int-range) or end (suffix-range) of the representation data.  Byte ranges do not use the other-range specifier."
fn validate_bytes_range_spec(spec: &str) -> Result<(), String> {
    // `1*DIGIT` is digits and nothing else, and at least one of them. Every
    // position in both forms is this production.
    //
    // cite(RFC 9110 § 14.1.1, label: int-range position grammar): "first-pos     = 1*DIGIT last-pos      = 1*DIGIT"
    let is_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());

    // cite(RFC 9110 § 14.1.1, label: suffix-range grammar): "suffix-range  = "-" suffix-length"
    // cite(RFC 9110 § 14.1.1, label: suffix-length grammar): "suffix-length = 1*DIGIT"
    // A suffix-length of zero is inside the production and outside the set of
    // satisfiable specifiers, which is a question about the representation rather
    // than the field, and so not this rule's to answer.
    // cite(RFC 9110 § 14.1.2): "A client can refer to the last N bytes (N > 0) of the selected representation using a suffix-range."
    if let Some(suffix_length) = spec.strip_prefix('-') {
        return if is_digits(suffix_length) {
            Ok(())
        } else {
            Err(format!(
                "suffix-range '{}' is not '-' followed by 1*DIGIT",
                spec
            ))
        };
    }

    // cite(RFC 9110 § 14.1.1, label: int-range grammar): "int-range     = first-pos "-" [ last-pos ]"
    let Some((first, last)) = spec.split_once('-') else {
        return Err(format!(
            "byte range-spec '{}' is neither an int-range nor a suffix-range",
            spec
        ));
    };
    if !is_digits(first) {
        return Err(format!("first-pos '{}' is not 1*DIGIT", first));
    }

    // The square brackets. A `first-pos` with no `last-pos` after it is the whole
    // remainder of the representation, which is what a client asks for when it
    // does not know how long the representation is -- so the empty half is a form
    // of the production and not a truncated value.
    //
    // cite(RFC 9110 § 14.1.2): "A client can limit the number of bytes requested without knowing the size of the selected representation.  If the last-pos value is absent, or if the value is greater than or equal to the current length of the representation data, the byte range is interpreted as the remainder of the representation"
    if last.is_empty() {
        return Ok(());
    }
    if !is_digits(last) {
        return Err(format!("last-pos '{}' is not 1*DIGIT", last));
    }

    // cite(RFC 9110 § 14.1.1): "An int-range is invalid if the last-pos value is present and less than the first-pos."
    if is_less_than(last, first) {
        return Err(format!(
            "last-pos {} is less than first-pos {}",
            last, first
        ));
    }
    Ok(())
}

/// Compare two `1*DIGIT` numerals as numerals, without turning them into
/// integers.
///
/// This comparison used to parse both sides into `u128` and report `first
/// byte-pos overflow` when that failed, so a 39-digit `first-pos` -- which
/// `1*DIGIT` admits without qualification -- was reported as invalid syntax,
/// with a test pinning it. The section that defines byte ranges says the
/// opposite in as many words: there is no predefined limit to the length of
/// content, so recipients must anticipate potentially large decimal numerals and
/// prevent parsing errors due to integer conversion overflows. The rule was
/// failing on precisely the input that sentence tells it to expect.
///
/// Length first, then digit order. With leading zeros stripped the longer
/// numeral is the larger one, and two of equal length compare as ASCII does.
/// Stripping them is not a tidy-up either: `1*DIGIT` permits `007`, so `007` and
/// `7` have to come out equal.
///
// cite(RFC 9110 § 14.1.2): "In the byte-range syntax, first-pos, last-pos, and suffix-length are expressed as decimal number of octets.  Since there is no predefined limit to the length of content, recipients MUST anticipate potentially large decimal numerals and prevent parsing errors due to integer conversion overflows."
fn is_less_than(a: &str, b: &str) -> bool {
    let (a, b) = (a.trim_start_matches('0'), b.trim_start_matches('0'));
    (a.len(), a) < (b.len(), b)
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &RangeHeaderSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_test_transaction;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn judge(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        let rule = RangeHeaderSyntax;
        crate::test_helpers::run_rule(
            &rule,
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
    // Every bytes range specifier § 14.1.2 prints, including the one whose
    // leading space its own list production does not generate, and the two it
    // labels valid but not canonical.
    #[case("bytes= 0-999, 4500-5499, -1000", false)]
    #[case("bytes=500-600,601-999", false)]
    #[case("bytes=500-700,601-999", false)]
    // Inside `suffix-length = 1*DIGIT` and outside the satisfiable specifiers,
    // which is a question about the representation and not about the field.
    #[case("bytes=-0", false)]
    // The unit name is case-insensitive, so the `bytes` checks reach these two.
    #[case("Bytes=0-1", false)]
    #[case("BYTES=5-3", true)]
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
    #[case("bytes=0-1-2", true)]
    #[case("bytes=0 - 499", true)]
    // `1*DIGIT` bounds neither position, and leading zeros are part of it.
    #[case("bytes=007-8", false)]
    #[case("bytes=8-007", true)]
    #[case(
        "bytes=340282366920938463463374607431768211456-340282366920938463463374607431768211457",
        false
    )]
    #[case(
        "bytes=340282366920938463463374607431768211457-340282366920938463463374607431768211456",
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
        for ex in RangeHeaderSyntax.examples() {
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
        let rule = RangeHeaderSyntax;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
