// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::field::{FIELD_LINE_DUPLICATED, RFC_9110_5_3};
use crate::violations::x_content_type_options::{
    FETCH_3_6, X_CONTENT_TYPE_OPTIONS_INVALID, X_CONTENT_TYPE_OPTIONS_MISSING,
};
use crate::violations::ViolationDef;

/// The three things that can be wrong with a field that has one useful value:
/// another value, none, or two of them.
static DECLARED: &[&ViolationDef] = &[
    &FIELD_LINE_DUPLICATED,
    &X_CONTENT_TYPE_OPTIONS_INVALID,
    &X_CONTENT_TYPE_OPTIONS_MISSING,
];

pub struct XContentTypeOptionsPresent;

#[derive(Debug, Clone)]
pub struct XContentTypeOptionsConfig {
    pub content_types: Vec<String>,
}

fn parse_x_content_type_options_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<XContentTypeOptionsConfig> {
    let Some(rule_config) = config.get_rule_config(rule_id) else {
        return Err(anyhow::anyhow!(
            "rule 'x_content_type_options_present' requires configuration to be enabled. Example:\n[rules.x_content_type_options_present]\nenabled = true\ncontent_types = [\"text/html\", \"application/json\"]"
        ));
    };

    let table = rule_config.as_table().ok_or_else(|| {
        anyhow::anyhow!(
            "Configuration for rule 'x_content_type_options_present' must be a TOML table with 'content_types' array"
        )
    })?;

    let value = table.get("content_types").ok_or_else(|| {
        anyhow::anyhow!("'content_types' field is required and must be an array of strings")
    })?;

    let arr = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("'content_types' must be an array"))?;
    if arr.is_empty() {
        return Err(anyhow::anyhow!("'content_types' array cannot be empty"));
    }

    let mut content_types = Vec::new();
    for (idx, item) in arr.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            anyhow::anyhow!("'content_types' item at index {} is not a string", idx)
        })?;
        content_types.push(s.to_ascii_lowercase());
    }

    Ok(XContentTypeOptionsConfig { content_types })
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const MDN_X_CONTENT_TYPE_OPTIONS: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "MDN X-Content-Type-Options",
    section: None,
    url:
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options",
    note: "Web Docs: X-Content-Type-Options",
};

impl RuleMeta for XContentTypeOptionsPresent {
    fn id(&self) -> &'static str {
        "x_content_type_options_present"
    }

    /// The types a deployment wants refused to a page that loads them as
    /// something they are not.
    ///
    /// **The field protects a response from the destination whose type it is
    /// not.** § 3.6.1 blocks a script-like destination any type that is not a
    /// JavaScript MIME type, and a `"style"` destination any essence that is
    /// not `text/css`. So the field never refuses a script its own type, or a
    /// stylesheet its own: `text/javascript` loaded as a script is allowed
    /// with or without it, and what it guards is that response loaded as a
    /// stylesheet. `text/css` is the mirror: guarded against a script load,
    /// and allowed as a stylesheet either way.
    ///
    /// `text/html` and `application/json` are refused to both destinations,
    /// and they are the types a cross-site page most wants to read as script:
    /// a document or an API answer carrying the user's data. That is the case
    /// the field exists for, and the reason no type is on this list for being
    /// what a script or a stylesheet is served as.
    ///
    /// Every type is refused to at least one of the two, so the list is a
    /// choice of which responses to ask about rather than a set the
    /// specification closes. A deployment serving another type it would not
    /// want read as script — `text/plain`, or whatever type its uploads are
    /// served as — adds it.
    ///
    // cite(Fetch § 3.6.1): "If destination is script-like and mimeType is failure or is not a JavaScript MIME type, then return blocked."
    // cite(Fetch § 3.6.1): "If destination is "style" and mimeType is failure or its essence is not "text/css", then return blocked."
    fn config_example(&self) -> &'static str {
        r#"enabled = true
content_types = ["text/html", "text/javascript", "application/javascript", "application/json", "text/css"]
"#
    }

    fn prepare(&self, cfg: &crate::config::Config) -> anyhow::Result<crate::rules::ResolvedRule> {
        let config = parse_x_content_type_options_config(cfg, self.id())?;
        // The two standard keys, **after** this rule's own options, so a config
        // naming a bad option still fails on that option.
        crate::rules::validate_rule_table(cfg, self.id())?;
        Ok(crate::rules::ResolvedRule {
            state: Box::new(config),
        })
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server X-Content-Type-Options")
    }

    fn description(&self) -> &'static str {
        "This rule checks if responses include the `X-Content-Type-Options: nosniff` header.\n\nThis security header prevents browsers from \"MIME-sniffing\" a response away from the declared `Content-Type`. This reduces exposure to drive-by download attacks and cross-site scripting (XSS) vulnerabilities where a browser might execute a file as HTML/JavaScript even if the server served it as an image or text.\n\nA header that is present but whose first value is not `nosniff` (matched case-insensitively, per the Fetch standard's determine-nosniff algorithm) is also flagged: it does not enable the protection.\n\nA response writing the field on more than one line is flagged too, whether or not the lines agree. Fetch \u{a7}3.6 defines the value as the single literal `nosniff` and gives it no comma-separated-list alternative, so RFC 9110 \u{a7}5.3's exception does not reach it; the splitting in *determine-nosniff* is a recipient recovering a first member from a value it should not have been sent, which is a recipient's rule and not a sender's licence. The repetition is reported in place of the value verdict, as it is for every other singleton field in this catalogue."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[FETCH_3_6, RFC_9110_5_3, MDN_X_CONTENT_TYPE_OPTIONS]
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
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/javascript\nX-Content-Type-Options: nosniff",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/javascript\n# Missing X-Content-Type-Options header",
            },
            // The mirror of the two above, published because it is the half a
            // reader would not guess from them: the script is guarded against
            // a stylesheet load, and a stylesheet is guarded against a script
            // load, since Fetch § 3.6.1 refuses each destination the types it
            // does not accept and a script load accepts no `text/css`.
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/css\n# Missing X-Content-Type-Options header",
            },
            // The other entry, which had no example at all: a server that wrote
            // the field and did not turn sniffing off. `sniff` is the word a
            // hand reaches for when it means the opposite of `nosniff`, and the
            // algorithm reads it as no opt-in at all rather than as a value it
            // does not recognise.
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/html\nX-Content-Type-Options: sniff",
            },
            // The third entry, and the one a reader is likeliest to think
            // harmless: both lines say `nosniff`, so the protection is on and
            // the defect is that the field was written twice. §5.3 does not ask
            // whether the lines agree — the exception it grants turns on the
            // field's definition, and this field has one literal and no list.
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/html\nX-Content-Type-Options: nosniff\nX-Content-Type-Options: nosniff",
            },
        ]
    }
}

impl Rule for XContentTypeOptionsPresent {
    fn needs_response(&self) -> bool {
        true
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
            let config: &XContentTypeOptionsConfig = ctx.state();
            let Some(resp) = &tx.response else {
                return None;
            };

            // The field is a singleton, so a second line is a defect before any
            // value on it is read. Fetch § 3.6 writes one literal and no
            // comma-separated-list alternative, which is what § 5.3's exception
            // turns on; the splitting in *determine-nosniff* is a recipient
            // recovering a first member from a value it should never have
            // received, on the same footing as RFC 9111 § 5.1's first-member
            // recovery for `Age` — a recipient's rule and not a sender's licence.
            //
            // **Reported instead of the value verdict, not beside it**, which is
            // what every sibling singleton in this catalogue does and is the one
            // place this field differs from them in what it costs. `values[0]` of
            // the recombined value is determinate here, so the check below would
            // still reach the right answer on two lines — but the repair an
            // operator owes is the same either way and one field cannot be two
            // findings, so the finding names the repetition, which is the defect
            // that came first.
            // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
            let lines = resp
                .headers
                .get_all("x-content-type-options")
                .iter()
                .count();
            if lines > 1 {
                return Some(ctx.report_with(
                    &FIELD_LINE_DUPLICATED,
                    crate::helpers::headers::singleton_field_preamble(
                        "X-Content-Type-Options",
                        lines,
                        &crate::helpers::headers::joined_field_lines_shown(
                            &resp.headers,
                            "x-content-type-options",
                        ),
                        "`X-Content-Type-Options = \"nosniff\"` (Fetch §3.6) is one literal \
                         and not a list",
                    ),
                ));
            }

            // A present header must actually enable the protection: browsers read the
            // first list element case-insensitively, so anything else means sniffing
            // stays on while the sender believes otherwise. A conforming extra element
            // after a valid first one is tolerated (the processing model ignores it).
            // cite(Fetch § 3.6): "X-Content-Type-Options = "nosniff" ; case-insensitive"
            // cite(Fetch § 3.6): "If values[0] is an ASCII case-insensitive match for "nosniff", then return true."
            if let Some(xcto) =
                crate::helpers::headers::get_header_str(&resp.headers, "x-content-type-options")
            {
                let first = xcto.split(',').next().unwrap_or("").trim();
                if !first.eq_ignore_ascii_case("nosniff") {
                    return Some(ctx.report_with(&X_CONTENT_TYPE_OPTIONS_INVALID, format!(
                            "X-Content-Type-Options value '{}' does not enable nosniff (the value must be `nosniff`, case-insensitive)",
                            xcto.trim()
                        )));
                }
            }

            // Get the response's content-type (without parameters)
            let content_type_header =
                crate::helpers::headers::get_header_str(&resp.headers, "content-type").and_then(
                    |s| {
                        crate::helpers::list::parse_semicolon_list(s)
                            .next()
                            .map(|v| v.to_ascii_lowercase())
                    },
                );

            if let Some(content_type) = content_type_header {
                // cite(Fetch § 3.6): "The `X-Content-Type-Options` response header can be used to require checking of a response’s `Content-Type` header against the destination of a request."
                // The 2xx gate is the rule's own tolerance (no sentence scopes the header
                // to successful responses). The configured content-type list stands in for
                // the request destination, which a proxy cannot know: the spec only blocks
                // for script-like and style destinations, and it blocks each of them the
                // types it does *not* accept, so the config names the types a deployment
                // wants refused to a page loading them as something they are not.
                // `config_example` says why each shipped type is there. That stand-in cannot hold for a
                // method whose destination is never script-like or style regardless of the
                // content-type carried: a CORS preflight (OPTIONS), a loopback diagnostic
                // (TRACE), and a tunnel's own response (CONNECT) are never fetched for
                // rendering or execution, so no content-type list stands in for anything.
                // cite(Fetch § 3.6.1): "Only request destinations that are script-like or "style" are considered as any exploits pertain to them."
                if !matches!(tx.request.method.as_str(), "OPTIONS" | "TRACE" | "CONNECT")
                    && (200..300).contains(&resp.status)
                    && config.content_types.contains(&content_type)
                    && !resp.headers.contains_key("x-content-type-options")
                {
                    return Some(ctx.report_with(
                        &X_CONTENT_TYPE_OPTIONS_MISSING,
                        missing_sentence(&content_type),
                    ));
                }
            }
            None
        };
        Vec::from_iter(finding())
    }
}

/// The essences MIME Sniffing calls a *JavaScript MIME type*, which is the set
/// § 3.6.1's script-like half compares against.
///
/// Written out because the finding's sentence depends on it: the field never
/// refuses a script one of these, so for such a response the stylesheet load
/// is the whole of what it guards.
// cite(MIME Sniffing § 4.6): "A JavaScript MIME type is any MIME type whose essence is one of the following:"
const JAVASCRIPT_MIME_TYPE_ESSENCES: &[&str] = &[
    "application/ecmascript",
    "application/javascript",
    "application/x-ecmascript",
    "application/x-javascript",
    "text/ecmascript",
    "text/javascript",
    "text/javascript1.0",
    "text/javascript1.1",
    "text/javascript1.2",
    "text/javascript1.3",
    "text/javascript1.4",
    "text/javascript1.5",
    "text/jscript",
    "text/livescript",
    "text/x-ecmascript",
    "text/x-javascript",
];

/// What the field would have refused this response to, named for its type.
///
/// **The destination a response is guarded against is the one whose type it is
/// not**, so the sentence differs by type: a script type is guarded only
/// against a stylesheet load, `text/css` only against a script load, and
/// anything else against both. One sentence for all three told an operator
/// serving a script that the field protects the script, which it cannot.
/// `essence` arrives lowercased, and the comparison is exact against the
/// lowercase set above.
// cite(Fetch § 3.6.1): "If destination is script-like and mimeType is failure or is not a JavaScript MIME type, then return blocked."
// cite(Fetch § 3.6.1): "If destination is "style" and mimeType is failure or its essence is not "text/css", then return blocked."
fn missing_sentence(essence: &str) -> String {
    let guarded = if JAVASCRIPT_MIME_TYPE_ESSENCES.contains(&essence) {
        "to a stylesheet load, whose destination accepts only `text/css`; a script load \
         accepts it either way, since it is a JavaScript MIME type"
    } else if essence == "text/css" {
        "to a script load, whose destination accepts only a JavaScript MIME type; a \
         stylesheet load accepts it either way"
    } else {
        "to a script load and to a stylesheet load, whose destinations accept only a \
         JavaScript MIME type and only `text/css`"
    };
    format!(
        "Response of type '{essence}' carries no `X-Content-Type-Options: nosniff`; with it, \
         Fetch \u{a7}3.6.1 would refuse the response {guarded}"
    )
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &XContentTypeOptionsPresent;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::enable_rule;
    use rstest::rstest;

    /// The repetition is reported *instead of* the value verdict, and one
    /// finding is all that comes back.
    ///
    /// The two lines here disagree, so both questions have an answer: the
    /// recombined `values[0]` is `sniff`, which does not opt in, and there are
    /// two field lines where the grammar allows one. A single-finding closure
    /// returning the first of them is only honest if there is exactly one, so
    /// the count is asserted rather than left to `run_rule` to hide.
    #[test]
    fn two_disagreeing_lines_draw_the_repetition_and_nothing_else() {
        let mut config = crate::config::Config::default();
        config.rules.insert(
            "x_content_type_options_present".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert(
                    "content_types".into(),
                    toml::Value::Array(vec![toml::Value::String("text/html".into())]),
                );
                t
            }),
        );

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[
                ("content-type", "text/html"),
                ("x-content-type-options", "sniff"),
                ("x-content-type-options", "nosniff"),
            ]),
            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        let found = crate::test_helpers::run_rule_all(
            &XContentTypeOptionsPresent,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert_eq!(found.len(), 1, "one field, one finding: {found:?}");
        assert_eq!(found[0].violation, "field_line_duplicated");
    }

    #[rstest]
    #[case(200, vec![("content-type", "text/html")], vec!["text/html"], true, Some("Response of type 'text/html' carries no `X-Content-Type-Options: nosniff`; with it, Fetch \u{a7}3.6.1 would refuse the response to a script load and to a stylesheet load, whose destinations accept only a JavaScript MIME type and only `text/css`"))]
    #[case(200, vec![("content-type", "text/javascript"), ("x-content-type-options", "nosniff")], vec!["text/javascript"], false, None)]
    #[case(404, vec![("content-type", "text/html")], vec!["text/html"], false, None)]
    #[case(101, vec![("content-type", "text/html")], vec!["text/html"], false, None)]
    #[case(200, vec![("content-type", "image/png")], vec!["text/html"], false, None)]
    #[case(200, vec![("content-type", "text/html; charset=utf-8")], vec!["text/html"], true, Some("Response of type 'text/html' carries no `X-Content-Type-Options: nosniff`; with it, Fetch \u{a7}3.6.1 would refuse the response to a script load and to a stylesheet load, whose destinations accept only a JavaScript MIME type and only `text/css`"))]
    // A present header must enable the protection: the first value is matched
    // ASCII case-insensitively against `nosniff`.
    #[case(200, vec![("content-type", "text/html"), ("x-content-type-options", "foobar")], vec!["text/html"], true, Some("X-Content-Type-Options value 'foobar' does not enable nosniff (the value must be `nosniff`, case-insensitive)"))]
    #[case(200, vec![("content-type", "text/html"), ("x-content-type-options", "NOSNIFF")], vec!["text/html"], false, None)]
    #[case(200, vec![("content-type", "text/html"), ("x-content-type-options", "nosniff, extra")], vec!["text/html"], false, None)]
    // The value check is independent of status and configured types: a malformed
    // security header is wrong wherever it is sent.
    #[case(404, vec![("content-type", "text/html"), ("x-content-type-options", "sniff")], vec!["text/html"], true, Some("X-Content-Type-Options value 'sniff' does not enable nosniff (the value must be `nosniff`, case-insensitive)"))]
    // A stylesheet is guarded against the destination it is not: a script
    // load, which accepts only a JavaScript MIME type, while a stylesheet load
    // accepts it either way. The sentence says so rather than the reverse. Both
    // directions, because a list that named the type and fired on it whatever
    // the field said would pass the first case alone.
    #[case(200, vec![("content-type", "text/css")], vec!["text/css"], true, Some("Response of type 'text/css' carries no `X-Content-Type-Options: nosniff`; with it, Fetch \u{a7}3.6.1 would refuse the response to a script load, whose destination accepts only a JavaScript MIME type; a stylesheet load accepts it either way"))]
    #[case(200, vec![("content-type", "text/css; charset=utf-8")], vec!["text/css"], true, Some("Response of type 'text/css' carries no `X-Content-Type-Options: nosniff`; with it, Fetch \u{a7}3.6.1 would refuse the response to a script load, whose destination accepts only a JavaScript MIME type; a stylesheet load accepts it either way"))]
    #[case(200, vec![("content-type", "text/css"), ("x-content-type-options", "nosniff")], vec!["text/css"], false, None)]
    // A script is guarded against a stylesheet load only: the script-like
    // half never refuses a JavaScript MIME type, so a sentence naming it would
    // tell the operator the field protects the script. `application/x-javascript`
    // is a spelling in the set and not in the shipped list; the sentence reads
    // the set, not the list. `text/plain` is in neither group and draws both.
    #[case(200, vec![("content-type", "text/javascript")], vec!["text/javascript"], true, Some("Response of type 'text/javascript' carries no `X-Content-Type-Options: nosniff`; with it, Fetch \u{a7}3.6.1 would refuse the response to a stylesheet load, whose destination accepts only `text/css`; a script load accepts it either way, since it is a JavaScript MIME type"))]
    #[case(200, vec![("content-type", "application/x-javascript")], vec!["application/x-javascript"], true, Some("Response of type 'application/x-javascript' carries no `X-Content-Type-Options: nosniff`; with it, Fetch \u{a7}3.6.1 would refuse the response to a stylesheet load, whose destination accepts only `text/css`; a script load accepts it either way, since it is a JavaScript MIME type"))]
    #[case(200, vec![("content-type", "text/plain")], vec!["text/plain"], true, Some("Response of type 'text/plain' carries no `X-Content-Type-Options: nosniff`; with it, Fetch \u{a7}3.6.1 would refuse the response to a script load and to a stylesheet load, whose destinations accept only a JavaScript MIME type and only `text/css`"))]
    // Two field lines are a defect before either value is read: Fetch §3.6
    // gives the field one literal and no list alternative, so §5.3's exception
    // does not reach it. The first pair is the shape a real origin sends —
    // both lines agreeing, so nothing is lost but the line — and the second is
    // the one that pins which finding wins when they disagree.
    #[case(200, vec![("content-type", "text/html"), ("x-content-type-options", "nosniff"), ("x-content-type-options", "nosniff")], vec!["text/html"], true, Some("X-Content-Type-Options is written on 2 header lines, which recombine into the one value 'nosniff, nosniff'; the field is a singleton \u{2014} `X-Content-Type-Options = \"nosniff\"` (Fetch \u{a7}3.6) is one literal and not a list \u{2014} so a sender must not generate more than one field line for it (RFC 9110 \u{a7}5.3)"))]
    #[case(200, vec![("content-type", "text/html"), ("x-content-type-options", "sniff"), ("x-content-type-options", "nosniff")], vec!["text/html"], true, Some("X-Content-Type-Options is written on 2 header lines, which recombine into the one value 'sniff, nosniff'; the field is a singleton \u{2014} `X-Content-Type-Options = \"nosniff\"` (Fetch \u{a7}3.6) is one literal and not a list \u{2014} so a sender must not generate more than one field line for it (RFC 9110 \u{a7}5.3)"))]
    fn check_response_cases(
        #[case] status: u16,
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] content_types: Vec<&str>,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = XContentTypeOptionsPresent;

        let mut config = crate::config::Config::default();
        config.rules.insert(
            "x_content_type_options_present".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert(
                    "content_types".into(),
                    toml::Value::Array(
                        content_types
                            .iter()
                            .map(|s| toml::Value::String(s.to_string()))
                            .collect(),
                    ),
                );
                t
            }),
        );

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice()),

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );

        if expect_violation {
            let found = violation.expect("a finding");
            // Three entries and two levels: a server that wrote the field meant
            // to opt in and did not, a server that wrote nothing never did, and
            // a server that wrote it twice broke §5.3 before either value was
            // read. The message tells them apart because each is worded by the
            // entry it reports, and none of the three could be worded as
            // another.
            let (id, severity) = if found.message.starts_with("Response of type") {
                (
                    "x_content_type_options_missing",
                    crate::lint::Severity::Info,
                )
            } else if found
                .message
                .starts_with("X-Content-Type-Options is written on")
            {
                ("field_line_duplicated", crate::lint::Severity::Error)
            } else {
                (
                    "x_content_type_options_invalid",
                    crate::lint::Severity::Error,
                )
            };
            assert_eq!(found.violation, id);
            assert_eq!(found.severity, severity);
            assert_eq!(Some(found.message), expected_message.map(|s| s.to_string()));
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[rstest]
    // A destination that is never script-like or style leaves no content-type
    // list to stand in for one: nothing fires however the type matches.
    #[case("OPTIONS", false)]
    #[case("TRACE", false)]
    #[case("CONNECT", false)]
    // POST carries no such exclusion — a document destination is still one a
    // browser renders and may execute against.
    #[case("POST", true)]
    #[case("GET", true)]
    fn check_response_excludes_non_script_methods(
        #[case] method: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = XContentTypeOptionsPresent;

        let mut config = crate::config::Config::default();
        config.rules.insert(
            "x_content_type_options_present".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert(
                    "content_types".into(),
                    toml::Value::Array(vec![toml::Value::String("text/html".into())]),
                );
                t
            }),
        );

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.to_string();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-type", "text/html")]),
            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );

        assert_eq!(violation.is_some(), expect_violation);
        Ok(())
    }

    #[rstest]
    #[case("missing_table", true, None)]
    #[case("non_table", true, Some("must be a TOML table"))]
    #[case("missing_field", true, None)]
    #[case("non_array", true, None)]
    #[case("non_string_item", true, Some("not a string"))]
    #[case("empty_array", true, Some("cannot be empty"))]
    #[case("valid", false, None)]
    fn validate_config_cases(
        #[case] scenario: &str,
        #[case] expect_error: bool,
        #[case] expected_substring: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = XContentTypeOptionsPresent;
        let mut cfg = crate::config::Config::default();

        match scenario {
            "missing_table" => {
                // No rule table at all
            }
            "non_table" => {
                cfg.rules.insert(
                    "x_content_type_options_present".to_string(),
                    toml::Value::String("not a table".to_string()),
                );
            }
            "missing_field" => {
                enable_rule(&mut cfg, "x_content_type_options_present");
            }
            "non_array" => {
                let mut table = toml::map::Map::new();
                table.insert("enabled".to_string(), toml::Value::Boolean(true));
                table.insert(
                    "content_types".to_string(),
                    toml::Value::String("text/html".to_string()),
                );
                cfg.rules.insert(
                    "x_content_type_options_present".to_string(),
                    toml::Value::Table(table),
                );
            }
            "non_string_item" => {
                let mut table = toml::map::Map::new();
                table.insert("enabled".to_string(), toml::Value::Boolean(true));
                table.insert(
                    "content_types".to_string(),
                    toml::Value::Array(vec![toml::Value::Integer(5)]),
                );
                cfg.rules.insert(
                    "x_content_type_options_present".to_string(),
                    toml::Value::Table(table),
                );
            }
            "empty_array" => {
                let mut table = toml::map::Map::new();
                table.insert("enabled".to_string(), toml::Value::Boolean(true));
                table.insert("content_types".to_string(), toml::Value::Array(vec![]));
                cfg.rules.insert(
                    "x_content_type_options_present".to_string(),
                    toml::Value::Table(table),
                );
            }
            "valid" => {
                let mut table = toml::map::Map::new();
                table.insert("enabled".to_string(), toml::Value::Boolean(true));
                table.insert(
                    "content_types".to_string(),
                    toml::Value::Array(vec![toml::Value::String("text/html".to_string())]),
                );
                cfg.rules.insert(
                    "x_content_type_options_present".to_string(),
                    toml::Value::Table(table),
                );
            }
            _ => panic!("unknown scenario"),
        }

        let res = rule.prepare(&cfg);
        if expect_error {
            assert!(res.is_err());
            if let Some(sub) = expected_substring {
                assert!(res.unwrap_err().to_string().contains(sub));
            }
        } else {
            res?;
            let parsed = super::parse_x_content_type_options_config(&cfg, rule.id())?;
            assert_eq!(parsed.content_types, vec!["text/html".to_string()]);
        }
        Ok(())
    }

    #[test]
    fn check_response_with_parameters_matches() -> anyhow::Result<()> {
        let rule = XContentTypeOptionsPresent;

        let status = 200;
        let mut config = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "content_types".to_string(),
            toml::Value::Array(vec![toml::Value::String("text/html".to_string())]),
        );
        config.rules.insert(
            "x_content_type_options_present".to_string(),
            toml::Value::Table(table),
        );

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "content-type",
                "text/html; charset=utf-8",
            )]),

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        // The absent field, at the level an absence no sentence asks about
        // takes — a server that never wrote it never opted in.
        let found = violation.expect("a finding");
        assert_eq!(found.violation, "x_content_type_options_missing");
        assert_eq!(found.severity, crate::lint::Severity::Info);
        Ok(())
    }

    #[test]
    fn check_missing_response() {
        let rule = XContentTypeOptionsPresent;
        let tx = crate::test_helpers::make_test_transaction();
        let mut config = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "content_types".to_string(),
            toml::Value::Array(vec![toml::Value::String("text/html".to_string())]),
        );
        config.rules.insert(
            "x_content_type_options_present".to_string(),
            toml::Value::Table(table),
        );
        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(violation.is_none());
    }

    /// The shipped list is a claim, and this is the claim run rather than read.
    ///
    /// What is asserted is that each type `config_example` gives a reason for
    /// draws the entry, under **the configuration the binary ships**, when the
    /// field is absent. `text/html` and `application/json` are refused to both
    /// destinations Fetch § 3.6.1 blocks for; `text/javascript` is refused to a
    /// stylesheet load and `text/css` to a script load, each the destination
    /// whose type it is not. A list that loses one of them fails this, and a
    /// list that gains a type does not.
    ///
    /// The `text/css` row is the one that failed first: the shipped list had no
    /// stylesheet type, so a stylesheet served without the field drew nothing.
    #[rstest]
    #[case("text/html")]
    #[case("application/json")]
    #[case("text/javascript")]
    #[case("text/css")]
    fn the_shipped_list_asks_about_every_type_it_gives_a_reason_for(#[case] content_type: &str) {
        let rule = XContentTypeOptionsPresent;

        let mut config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let mut table = rule
            .config_example()
            .parse::<toml::Table>()
            .expect("the rule's own config example parses");
        table.insert("enabled".into(), toml::Value::Boolean(true));
        config
            .rules
            .insert(rule.id().to_string(), toml::Value::Table(table));

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "content-type",
                content_type,
            )]),
            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        let found = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        )
        .unwrap_or_else(|| panic!("the shipped list says nothing about {content_type}"));
        assert_eq!(found.violation, "x_content_type_options_missing");
    }

    #[test]
    fn id_and_scope_are_expected() {
        let rule = XContentTypeOptionsPresent;
        assert_eq!(rule.id(), "x_content_type_options_present");
        assert!(rule.needs_response());
    }
}
