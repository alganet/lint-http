// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{
    combined_field_value_as_written, describe_char, is_nominated_by_connection,
    list_members_as_written, shown_in_finding, token_or_quoted_string, trim_ows, WordDefect,
};
use crate::lint::Violation;
use crate::rules::Rule;

#[derive(Debug, Clone)]
pub struct MessageKeepAliveConfig {
    pub severity: crate::lint::Severity,
    pub max_timeout_seconds: u64,
}

/// Read this rule's configuration.
///
/// `max_timeout_seconds` is required and has no default, because it is the one
/// thing in this rule that no document decides: nothing published states a
/// maximum for the `timeout` parameter, so the bound is a deployment's policy
/// and an absent key would make the rule invent one. A parse failure stops the
/// whole rule rather than the one branch it feeds, so a config mistake cannot
/// read as a clean run of the grammar checks.
fn parse_keep_alive_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<MessageKeepAliveConfig> {
    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;

    let rule_cfg = config.get_rule_config(rule_id).ok_or_else(|| {
        anyhow::anyhow!(
            "rule '{}' requires configuration and a 'max_timeout_seconds' integer value (seconds)",
            rule_id
        )
    })?;

    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let mt = table.get("max_timeout_seconds").ok_or_else(|| {
        anyhow::anyhow!(
            "Rule '{}' requires a 'max_timeout_seconds' integer value in seconds (e.g., 3600)",
            rule_id
        )
    })?;

    let mt_int = mt
        .as_integer()
        .ok_or_else(|| anyhow::anyhow!("'max_timeout_seconds' must be an integer"))?;

    if mt_int <= 0 {
        return Err(anyhow::anyhow!(
            "'max_timeout_seconds' must be a positive integer"
        ));
    }

    Ok(MessageKeepAliveConfig {
        severity,
        max_timeout_seconds: mt_int as u64,
    })
}

pub struct MessageKeepAliveHeaderValidity;

impl Rule for MessageKeepAliveHeaderValidity {
    fn id(&self) -> &'static str {
        "message_keep_alive_header_validity"
    }

    /// Either side of a connection writes this field, and the section that
    /// specifies it says so in the sentence that permits it at all.
    // cite(RFC 2068 § 19.7.1.1): "When the Keep-Alive connection-token has been transmitted with a request or a response, a Keep-Alive header field MAY also be included."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn validate(&self, config: &crate::config::Config) -> anyhow::Result<()> {
        parse_keep_alive_config(config, self.id())?;
        // The two standard keys, **after** this rule's own options, so a config
        // naming a bad option still fails on that option. `enabled` is checked
        // here because the parser above stopped reading it: that read ran once
        // per message at lint time and the flag was discarded, since
        // `PreparedEngine` had already decided whether the rule runs.
        crate::rules::validate_rule_table(config, self.id())?;
        Ok(())
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        // The field probe is one lookup per section; `parse_keep_alive_config`
        // is several map probes and a hash of the rule id. Nearly every message
        // carries no `Keep-Alive`, so the config is read only once the field is
        // known to be here.
        if !tx.request.headers.contains_key("keep-alive")
            && !tx
                .response
                .as_ref()
                .is_some_and(|resp| resp.headers.contains_key("keep-alive"))
        {
            return None;
        }

        let config = parse_keep_alive_config(cfg, self.id()).ok()?;
        let message = judge(
            &tx.request.headers,
            &tx.request.version,
            "Request",
            config.max_timeout_seconds,
        )
        .or_else(|| {
            tx.response.as_ref().and_then(|resp| {
                judge(
                    &resp.headers,
                    &resp.version,
                    "Response",
                    config.max_timeout_seconds,
                )
            })
        })?;

        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message,
        })
    }

    fn description(&self) -> &'static str {
        "Parses the `Keep-Alive` field of a request and of a response — every field line of one \
         section joined into the single list they are — against the grammar that defines it: \
         `Keep-Alive-header = \"Keep-Alive\" \":\" 0# keepalive-param`, where \
         `keepalive-param = param-name \"=\" value` and `value = token | quoted-string`. It also \
         reports the field's one requirement on a sender: a `Keep-Alive` written without the \
         matching `keep-alive` connection option in `Connection`.\
         \n\n\
         **The document is RFC 2068, and the current specification is what says so.** RFC 9110 \
         §7.6.1 lists the fields an intermediary should remove before forwarding and names each \
         one's source; against `Keep-Alive` it writes *Section 19.7.1 of [RFC2068]*. RFC 2616 \
         removed the grammar rather than restating it and pointed back the same way, and the IANA \
         HTTP Field Name Registry registers the field `permanent` with RFC 2068 as its only \
         reference. So this is not a field nothing specifies — it is a field whose specification \
         is an obsoleted document that the current one still names, and both are named here.\
         \n\n\
         Reading it from that document rather than from RFC 9110 changes three answers.\
         \n\n\
         - **Whitespace around the `=` is conforming.** RFC 2068 §2.1's `implied *LWS` rule lets \
         linear whitespace sit between any token and any delimiter, so `timeout = 30` is the same \
         parameter as `timeout=30`. A field whose grammar RFC 9110 writes would need `BWS` printed \
         in the production for that, and a sender writing it there would be the finding.\
         \n\
         - **An empty member is not a finding.** RFC 2068 §2.1's `#rule` says null elements are \
         allowed, where RFC 9110 §5.6.1.1 makes one a sender's MUST NOT. `Keep-Alive: timeout=30,,\
         max=100` is reported by nothing here.\
         \n\
         - **An empty field value is not a finding either.** The list is `0#`, with no minimum, so \
         `Keep-Alive:` declares no parameter rather than declaring one badly.\
         \n\n\
         **`timeout` is named by no document that is in force.** RFC 2068 writes the field's \
         grammar and then says *\"HTTP/1.1 does not define any parameters.\"* The only document \
         that ever gave `timeout` a value grammar and a meaning is \
         draft-thomson-hybi-http-timeout-03, an individual Internet-Draft that expired in January \
         2013, and its `\"timeout\" \"=\" delta-seconds` is quoted here as the only published \
         reading of a value servers send anyway — not as a requirement. What that costs is worth \
         being explicit about: a `timeout` whose value is a well-formed `token` or `quoted-string` \
         satisfies RFC 2068's `keepalive-param` no matter what it holds, so `timeout=\"60\"` and \
         `timeout=+30` are reported against the draft's grammar alone. The draft would also have \
         made the `=` optional (`keep-alive-extension = token [ \"=\" ( token / quoted-string ) ]`); \
         RFC 2068 writes it into the production, and the document in force is what decides, so \
         `Keep-Alive: max` is reported and the finding says which reading it comes from.\
         \n\n\
         **`max_timeout_seconds` is this deployment's policy and not a requirement.** No document \
         states any maximum for the parameter. The bound is required rather than defaulted so that \
         the number in a finding is one an operator chose, and the finding names the config key \
         rather than advising a smaller value. A configuration this rule cannot read stops the \
         whole rule, grammar checks included.\
         \n\n\
         **What this rule does not decide.**\
         \n\n\
         - **What a `param-name` may hold.** `keepalive-param = param-name \"=\" value` is the only \
         place RFC 2068 writes the name `param-name`, and the document defines it nowhere. There is \
         no production to measure a name against, so no name is reported for its spelling — only \
         for being absent, or for having no `=` and no value after it.\
         \n\
         - **Whether `max` should have been sent.** The expired draft deprecates it. Deprecation \
         there is a sentence in a document that is not in force, and RFC 2068 forbids no parameter \
         name at all.\
         \n\
         - **`timeout=0`.** `delta-seconds` is `1*DIGIT` and generates it, and a host announcing \
         that it will close an idle connection immediately has said something true about itself. \
         No sentence makes it a defect.\
         \n\
         - **The field over HTTP/2 and HTTP/3.** Both versions forbid connection-specific fields \
         outright, which is a different finding from a malformed value and belongs to the rules \
         that own the version. `message_no_connection_specific_fields` reports both halves, each \
         against the version that carried the field section it is in. The connection-option requirement here \
         is gated to HTTP/1.x for the same reason — demanding `Connection: keep-alive` of an \
         HTTP/2 message would be advice to violate RFC 9113 §8.2.2.\
         \n\
         - **Whether the timeout was honoured.** The draft's own sentence about it is a MAY paired \
         with a SHOULD about a host's future behaviour, which no capture records."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 2068",
                section: Some("19.7.1.1"),
                url: "https://www.rfc-editor.org/rfc/rfc2068.html#section-19.7.1.1",
                note: "The `Keep-Alive` grammar, the sentence saying HTTP/1.1 defines no \
                       parameters for it, and the field's one requirement on a sender — the \
                       matching connection token. Obsoleted, and still the document RFC 9110 \
                       §7.6.1 names for this field, so this is where the productions are read \
                       from. The reference here used to be RFC 7230 §6.7, which is `Upgrade`",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("7.6.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1",
                note: "The current specification's own pointer: `Keep-Alive` appears in the list \
                       of fields an intermediary should remove before forwarding, annotated \
                       *Section 19.7.1 of [RFC2068]*. It is also what makes the field \
                       connection-specific, and therefore hop-by-hop",
            },
            crate::rules::SpecRef {
                spec: "RFC 2068",
                section: Some("2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc2068.html#section-2.1",
                note: "The two notation rules that make this field's list read differently from a \
                       field RFC 9110 defines: `#rule` permits null elements, and `implied *LWS` \
                       permits whitespace between a token and a delimiter — which is what makes \
                       `timeout = 30` conforming rather than a `BWS` defect",
            },
            crate::rules::SpecRef {
                spec: "RFC 2068",
                section: Some("2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc2068.html#section-2.2",
                note: "`token`, `tspecials`, `LWS` and `quoted-string`. This document's `token` \
                       admits exactly the characters RFC 9110 §5.6.2's `tchar` does — the \
                       seventeen `tspecials` are RFC 9110's delimiters and both alphabets stop at \
                       US-ASCII — so the shared helper is the same production under another name",
            },
            crate::rules::SpecRef {
                spec: "RFC 2068",
                section: Some("3.7"),
                url: "https://www.rfc-editor.org/rfc/rfc2068.html#section-3.7",
                note: "`value = token | quoted-string`, the right-hand half of `keepalive-param`. \
                       The rule name is defined once for the document and `keepalive-param` uses \
                       it, which is why a parameter value may be quoted at all",
            },
            crate::rules::SpecRef {
                spec: "RFC 2068",
                section: Some("4.2"),
                url: "https://www.rfc-editor.org/rfc/rfc2068.html#section-4.2",
                note: "This document's statement of the rule that makes repeated field lines one \
                       list — the same requirement RFC 9110 §5.2 states, which is what the shared \
                       line-joining helper cites",
            },
            crate::rules::SpecRef {
                spec: "draft-thomson-hybi-http-timeout-03",
                section: Some("2"),
                url: "https://www.ietf.org/archive/id/draft-thomson-hybi-http-timeout-03.txt",
                note: "The only document that ever gave `timeout` a grammar or a meaning. An \
                       individual Internet-Draft, never adopted, expired 2013-01-18 — quoted as \
                       the only published reading of the parameter and never as a requirement. \
                       Its §2.2.1 deprecates `max`; its §7.2 asks IANA for a registry that was \
                       never created, which is why this rule carries no list of parameter names",
            },
            crate::rules::SpecRef {
                spec: "RFC 9111",
                section: Some("1.2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-1.2.2",
                note: "`delta-seconds = 1*DIGIT`, the production the draft's `timeout` value is. \
                       `1*DIGIT` is what a leading `+` fails, and a standard-library integer \
                       parser accepts",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2",
                note:
                    "The sender MUST NOT behind every grammar finding here: a value that derives \
                       from none of the productions is a protocol element matching no ABNF rule",
            },
            crate::rules::SpecRef {
                spec: "RFC 2616",
                section: Some("19.6.2"),
                url: "https://www.rfc-editor.org/rfc/rfc2616.html#section-19.6.2",
                note: "Where the grammar stopped being restated: RFC 2616 kept the compatibility \
                       discussion and sent the reader back to RFC 2068 for the field itself. The \
                       same shape as RFC 9111 §5.5 and `Warning`",
            },
            crate::rules::SpecRef {
                spec: "IANA HTTP Field Name Registry",
                section: None,
                url: "https://www.iana.org/assignments/http-fields/http-fields.xhtml",
                note: "`Keep-Alive` is registered `permanent`, with RFC 2068 as its only \
                       reference — not `obsoleted`, unlike `Warning`. Corroboration for reading \
                       an obsoleted document, not an authority this rule enforces",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nConnection: keep-alive\nKeep-Alive: timeout=30, max=100",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(whitespace around the \"=\" is implied *LWS)"),
                snippet: "HTTP/1.1 200 OK\nConnection: keep-alive\nKeep-Alive: timeout = 30",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(an empty member, which RFC 2068's #rule permits)"),
                snippet: "HTTP/1.1 200 OK\nConnection: keep-alive\nKeep-Alive: timeout=30,,max=100",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(timeout=0 is a delta-seconds and says something true)"),
                snippet: "HTTP/1.1 200 OK\nConnection: keep-alive\nKeep-Alive: timeout=0",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(an extension parameter whose quoted value holds a comma)"),
                snippet:
                    "HTTP/1.1 200 OK\nConnection: keep-alive\nKeep-Alive: timeout=30, note=\"a, b\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(no connection option naming the field)"),
                snippet: "HTTP/1.1 200 OK\nKeep-Alive: timeout=30",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a parameter with no \"=\" and no value)"),
                snippet: "HTTP/1.1 200 OK\nConnection: keep-alive\nKeep-Alive: timeout=30, max",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a leading + is not a DIGIT)"),
                snippet: "HTTP/1.1 200 OK\nConnection: keep-alive\nKeep-Alive: timeout=+30",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a quoted timeout is a keepalive-param and not a delta-seconds)"),
                snippet: "HTTP/1.1 200 OK\nConnection: keep-alive\nKeep-Alive: timeout=\"60\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(above the configured max_timeout_seconds)"),
                snippet: "HTTP/1.1 200 OK\nConnection: keep-alive\nKeep-Alive: timeout=999999",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a value that is neither a token nor a quoted-string)"),
                snippet:
                    "HTTP/1.1 200 OK\nConnection: keep-alive\nKeep-Alive: timeout=30, note=a b",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageKeepAliveHeaderValidity;

/// Judge one section's `Keep-Alive`, if it carries one.
///
/// The field lines of a section are joined into the one list they are, over the
/// raw octets: `token` stops at US-ASCII, so an octet at or above %x80 is a
/// finding where it stands in a `token` and is ordinary data inside a
/// `quoted-string` (`qdtext` is *any TEXT except DQUOTE*, and `TEXT` is any
/// OCTET except CTLs). Reading the value through `to_str` would fold both cases
/// — and a HTAB, which is `LWS` — into "this message has no `Keep-Alive`", or
/// into a claim about the value's encoding.
fn judge(
    headers: &hyper::HeaderMap,
    version: &str,
    side: &str,
    max_timeout_seconds: u64,
) -> Option<String> {
    let value = combined_field_value_as_written(headers, "keep-alive")?;

    validate_keep_alive(&value, max_timeout_seconds)
        .err()
        .or_else(|| missing_connection_option(headers, version))
        .map(|e| format!("{side} Keep-Alive header: {e}"))
}

/// The field's one requirement on a sender: it travels with its connection
/// option or it does not travel.
///
/// The grammar is judged first, so a member that derives from nothing is
/// reported as itself rather than as this. Both are true of such a message and
/// a rule returns one finding.
///
/// The gate is the message's own version. `Connection` has no meaning in HTTP/2
/// or HTTP/3 and both forbid the field outright, so asking an HTTP/2 sender for
/// a connection option would be asking it to violate RFC 9113 §8.2.2 —
/// `message_no_connection_specific_fields` owns that question for both versions.
// cite(RFC 9110 § 7.6.1): "Keep-Alive (Section 19.7.1 of [RFC2068])"
fn missing_connection_option(headers: &hyper::HeaderMap, version: &str) -> Option<String> {
    if !crate::http_version::is_major(version, 1) {
        return None;
    }
    let connection = combined_field_value_as_written(headers, "connection");
    // cite(RFC 2068 § 19.7.1.1): "If the Keep-Alive header is sent, the corresponding connection token MUST be transmitted."
    if is_nominated_by_connection("keep-alive", connection.as_deref()) {
        return None;
    }
    Some(
        "the field was sent with no `keep-alive` connection option in `Connection`, and the \
         corresponding connection token must be transmitted with it"
            .into(),
    )
}

/// Validate a whole `Keep-Alive` field value.
// cite(RFC 9110 § 2.2): "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules."
// cite(RFC 2068 § 19.7.1.1): "Keep-Alive-header = "Keep-Alive" ":" 0# keepalive-param"
fn validate_keep_alive(value: &str, max_timeout_seconds: u64) -> Result<(), String> {
    // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace."
    let v = trim_ows(value);

    // The members are cut at the top-level commas only: a `value` may be a
    // `quoted-string` and hold one as data. Each is trimmed as it is reached
    // rather than in a pass of its own, so a value failing at its first member
    // stops there.
    for (index, member) in list_members_as_written(v).into_iter().enumerate() {
        let n = index + 1;

        // Two sentences of this document decide that an empty member is not a
        // finding, and both differ from the field RFC 9110 would have defined.
        // The list is `0#` -- no minimum, so a value carrying no parameter at
        // all is a value -- and this notation permits a null element between
        // two real ones, where RFC 9110 §5.6.1.1 makes one a sender's MUST NOT.
        // cite(RFC 2068 § 2.1): "Wherever this construct is used, null elements are allowed, but do not contribute"
        // cite(RFC 2068 § 19.7.1.1): "The Keep-Alive header itself is optional, and is used only if a parameter is being sent."
        if member.is_empty() {
            continue;
        }

        validate_keepalive_param(member, max_timeout_seconds)
            .map_err(|e| format!("member {n} {e}"))?;
    }

    Ok(())
}

/// Validate one `keepalive-param`.
///
/// The `=` and the value are both written into the production, so a bare name
/// derives from nothing. The expired draft's `keep-alive-extension` would have
/// made them optional; the document in force is this one, and the finding says
/// which reading it comes from rather than picking one silently.
///
/// **This is a lookalike of [`parse_token_bws_word`], not a fourth caller of
/// it.** That helper owns `token [ BWS "=" BWS word ]` -- the one production
/// `preference`, `parameter` and `applied-pref` share -- and `BWS` is the
/// terminal that tells it apart from the twenty-odd other `splitn(2, '=')`
/// sites in this tree. `keepalive-param` writes no `BWS`: whitespace beside its
/// `=` is admitted by RFC 2068's document-wide *implied \*LWS* notation rule
/// instead, which is not a terminal at all. The two productions also disagree on
/// both halves -- the helper measures its name against `token`, and a
/// `param-name` has no production to measure against; the helper's `word` is
/// RFC 9110's and returns the value *unescaped*, where `value` is RFC 2068's and
/// is only judged. Folding this into the helper would give it a mode switch per
/// disagreement and answer none of them better.
///
/// [`parse_token_bws_word`]: crate::helpers::headers::parse_token_bws_word
// cite(RFC 2068 § 19.7.1.1): "keepalive-param = param-name "=" value"
// cite(draft-thomson-hybi-http-timeout-03 § 2): "keep-alive-extension = token [ "=" ( token / quoted-string ) ]"
fn validate_keepalive_param(member: &str, max_timeout_seconds: u64) -> Result<(), String> {
    // The production writes one `"="`, so the first one is it and everything
    // after belongs to the value -- which is judged whole, so a `quoted-string`
    // carrying more of them keeps them. `=` is one of the `tspecials` the
    // sentence below calls a delimiter, which is why it can end the name at all.
    // (The `tspecials` production itself is uncitable: its `<">` alternative
    // leaves the quotation marks in the line unpaired, and this cite grammar has
    // no escape for that.)
    // cite(RFC 2068 § 2.1): "At least one delimiter (tspecials) must exist between any two tokens, since they would otherwise be interpreted as a single token."
    let Some(eq) = member.find('=') else {
        return Err(format!(
            "is `{}`, which has no \"=\" and no value after it; the draft that named these \
             parameters would have allowed that and the document specifying the field does not",
            shown_in_finding(member)
        ));
    };

    // Whitespace either side of the `=` is not slack this rule is granting: the
    // notation puts it there. That is the opposite answer from a field whose
    // grammar RFC 9110 writes, where the same characters would be `BWS` and the
    // sender's defect.
    // cite(RFC 2068 § 2.1): "linear whitespace (LWS) can be included between any two adjacent words (token or quoted-string), and between adjacent tokens and delimiters (tspecials), without changing the interpretation of a field."
    // cite(RFC 2068 § 2.2, label: LWS grammar): "LWS            = [CRLF] 1*( SP | HT )"
    let name = trim_ows(&member[..eq]);
    let value = trim_ows(&member[eq + 1..]);

    // `param-name` is used here and defined nowhere in the document, so there is
    // no production a name can be measured against and none is applied. Its
    // absence is a different question: a member that is only a value names no
    // parameter at all.
    if name.is_empty() {
        return Err("begins with its \"=\", so it names no parameter".into());
    }

    validate_param_value(value)?;

    // The parameter is the whole subject of this rule and no document in force
    // names it. The comparison folds case because the only grammar that writes
    // the name writes it as an ABNF string literal, which RFC 5234 §2.3 makes
    // case-insensitive.
    // cite(draft-thomson-hybi-http-timeout-03 § 2): "keep-alive-info      =   "timeout" "=" delta-seconds"
    // cite(RFC 2068 § 19.7.1.1): "HTTP/1.1 does not define any parameters."
    if name.eq_ignore_ascii_case("timeout") {
        validate_timeout(value, max_timeout_seconds)?;
    }

    Ok(())
}

/// Validate the right-hand half of a `keepalive-param`.
///
/// The alternation is decided by the first octet, because only one branch of it
/// can begin with a DQUOTE: `token` excludes that character as a `tspecials`.
/// That decision, and the two measurements behind it, is
/// [`token_or_quoted_string`]'s -- **written out seven times in this tree until
/// P2 gave it a home**, here and in `message_pragma_token_valid`,
/// `message_cache_control_token_valid`,
/// `message_accept_header_media_type_syntax`,
/// `server_alt_svc_header_syntax::check_parameter`,
/// `server_server_timing_header_syntax::check_param` and privately inside
/// [`parse_token_bws_word`]. What could not be shared and is not shared is the
/// wording, and the verdict on an empty value: two of the seven tolerate it on
/// the record and five do not.
///
/// This document's `token` and `quoted-string` are RFC 2068's, and the reader's
/// are RFC 9110's. The seventeen `tspecials` are § 5.6.2's delimiters, both
/// alphabets stop at US-ASCII, and RFC 2068's own prose licenses the backslash
/// inside a quoted-string -- which is what RFC 2616 § 2.2 later wrote into the
/// production and RFC 9110 § 5.6.4 still has. So the two documents' pairs are
/// the same pair, and the cites below are why that is a reading rather than an
/// assumption.
///
/// [`token_or_quoted_string`]: crate::helpers::headers::token_or_quoted_string
/// [`parse_token_bws_word`]: crate::helpers::headers::parse_token_bws_word
// cite(RFC 2068 § 3.7): "value          = token | quoted-string"
// cite(RFC 2068 § 2.2): "token          = 1*<any CHAR except CTLs or tspecials>"
// cite(RFC 2068 § 2.2): "quoted-string  = ( <"> *(qdtext) <"> )"
// cite(RFC 2068 § 2.2): "The backslash character ("\") may be used as a single-character quoting mechanism only within quoted-string and comment constructs."
fn validate_param_value(value: &str) -> Result<(), String> {
    match token_or_quoted_string(value) {
        Ok(_) => Ok(()),
        // Neither alternative derives the empty string -- `token` is `1*<...>`
        // and a `quoted-string` is at least its two DQUOTEs -- so a member
        // ending on its `=` has a value the grammar cannot generate. No
        // sentence in this document tolerates it, so it is a finding here.
        Err(WordDefect::Empty) => Err(
            "has nothing after its \"=\", and neither a token nor a quoted-string derives the \
             empty string"
                .into(),
        ),
        Err(WordDefect::NotToken(c)) => Err(format!(
            "has {} in its value, and a value that is not a quoted-string is a token",
            describe_char(c)
        )),
        // The reader builds this half of its message and puts the value into it
        // raw. The only octets a `HeaderValue` can carry that `describe_octet`
        // would have named are `obs-text`, and those are `qdtext` -- so one
        // reaches a finding here only inside a quoted-string that is already
        // malformed. Rendering them is the helper's to fix, at its callers.
        Err(WordDefect::NotQuotedString(e)) => Err(format!(
            "has a value that is not a well-formed quoted-string: {e}"
        )),
    }
}

/// Validate a `timeout` against the only grammar ever published for it, and
/// then against the bound this deployment configured.
///
/// The two are separate answers on purpose. The first is a reading of a
/// document; the second is a policy, and the finding says so rather than
/// advising a smaller number.
// cite(draft-thomson-hybi-http-timeout-03 § 2.1): "The value of the "timeout" parameter is a single integer in seconds."
// cite(RFC 9111 § 1.2.2): "delta-seconds  = 1*DIGIT"
fn validate_timeout(value: &str, max_timeout_seconds: u64) -> Result<(), String> {
    // Every character against the production before any of it reaches a number
    // parser: `u64::from_str` accepts a leading `+`, and no `delta-seconds`
    // does.
    if let Some(c) = value.chars().find(|c| !c.is_ascii_digit()) {
        return Err(format!(
            "has {} in its timeout, and the only published grammar for the parameter writes a \
             delta-seconds, which is 1*DIGIT",
            describe_char(c)
        ));
    }

    // The value is all digits, so a parse failure here is arithmetic rather than
    // syntax -- a number too large for the accumulator is larger than any bound
    // an operator can configure.
    let seconds = value.parse::<u64>().unwrap_or(u64::MAX);
    if seconds > max_timeout_seconds {
        return Err(format!(
            "has a timeout of {value} seconds, above the max_timeout_seconds of \
             {max_timeout_seconds} this deployment configured; no document states a maximum"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// The rule's config table, with `max_timeout_seconds` written only when the
    /// case supplies one — the `None` shape is what the required-key tests need,
    /// and it is the same table.
    fn cfg_with_optional_max(max: Option<i64>) -> crate::config::Config {
        let rule = MessageKeepAliveHeaderValidity;
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        cfg.rules.insert(
            rule.id().into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                if let Some(m) = max {
                    t.insert("max_timeout_seconds".into(), toml::Value::Integer(m));
                }
                t
            }),
        );
        cfg
    }

    fn cfg_with_max(max: i64) -> crate::config::Config {
        cfg_with_optional_max(Some(max))
    }

    /// Build a response carrying `Connection: keep-alive` plus whatever the case
    /// supplies, so a negative case is a message the rule would otherwise report
    /// on rather than one that is clean before it starts.
    fn response_with(keep_alive: Option<&str>) -> crate::http_transaction::HttpTransaction {
        let mut pairs: Vec<(&str, &str)> = vec![("connection", "keep-alive")];
        if let Some(v) = keep_alive {
            pairs.push(("keep-alive", v));
        }
        crate::test_helpers::make_test_transaction_with_response(200, &pairs)
    }

    /// The same fixture with the field written as raw octets, which is the only
    /// way to put an `obs-text` or a HTAB into it — `make_headers_from_pairs`
    /// takes a `&str`.
    fn response_with_raw(keep_alive: &[u8]) -> crate::http_transaction::HttpTransaction {
        use hyper::header::HeaderValue;
        let mut tx = response_with(None);
        tx.response
            .as_mut()
            .expect("the fixture has a response")
            .headers
            .append(
                "keep-alive",
                HeaderValue::from_bytes(keep_alive).expect("a HeaderValue can hold these octets"),
            );
        tx
    }

    fn check(tx: &crate::http_transaction::HttpTransaction, max: i64) -> Option<Violation> {
        MessageKeepAliveHeaderValidity.check_transaction(
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg_with_max(max),
        )
    }

    #[rstest]
    // The grammar's own shapes.
    #[case("timeout=30, max=100", false)]
    #[case("timeout=30", false)]
    #[case("max=100", false)]
    #[case("", false)]
    #[case(",", false)]
    #[case("timeout=30,,max=100", false)]
    // Implied *LWS around the delimiter: RFC 2068 puts it there.
    #[case(" timeout =  30 ", false)]
    // A value may be quoted, and its comma is data.
    #[case("timeout=30, note=\"a, b\"", false)]
    // `=` and a value are both in the production.
    #[case("max", true)]
    #[case("timeout=30, max", true)]
    #[case("timeout=", true)]
    #[case("=30", true)]
    // `value = token | quoted-string`.
    #[case("note=a b", true)]
    #[case("note=\"unterminated", true)]
    #[case("note=(x)", true)]
    // `delta-seconds` is 1*DIGIT, which a leading sign and a quoted value fail.
    #[case("timeout=+30", true)]
    #[case("timeout=\"60\"", true)]
    #[case("timeout=30.5", true)]
    #[case("timeout=bad", true)]
    // Zero is a delta-seconds and no sentence forbids it.
    #[case("timeout=0", false)]
    // The configured bound.
    #[case("timeout=3600", false)]
    #[case("timeout=3601", true)]
    #[case("timeout=99999999999999999999999", true)]
    fn members_are_judged_against_the_production(
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) {
        let found = check(&response_with(Some(value)), 3600);
        assert_eq!(
            found.is_some(),
            expect_violation,
            "for {value:?}: {found:?}"
        );
    }

    /// Every finding is a member's index followed by a verb phrase, and the two
    /// halves are written in different functions. Asserting `is_some` cannot see
    /// them fail to join, which is how "member 1 's timeout is ..." survived
    /// being written.
    #[rstest]
    #[case(
        "timeout=30, max",
        "Response Keep-Alive header: member 2 is `max`, which has no \"=\" and no value after \
         it; the draft that named these parameters would have allowed that and the document \
         specifying the field does not"
    )]
    #[case(
        "timeout=",
        "Response Keep-Alive header: member 1 has nothing after its \"=\", and neither a token \
         nor a quoted-string derives the empty string"
    )]
    #[case(
        "=30",
        "Response Keep-Alive header: member 1 begins with its \"=\", so it names no parameter"
    )]
    #[case(
        "note=a b",
        "Response Keep-Alive header: member 1 has ' ' in its value, and a value that is not a \
         quoted-string is a token"
    )]
    #[case(
        "timeout=+30",
        "Response Keep-Alive header: member 1 has '+' in its timeout, and the only published \
         grammar for the parameter writes a delta-seconds, which is 1*DIGIT"
    )]
    #[case(
        "timeout=3601",
        "Response Keep-Alive header: member 1 has a timeout of 3601 seconds, above the \
         max_timeout_seconds of 3600 this deployment configured; no document states a maximum"
    )]
    fn a_finding_reads_as_one_sentence(#[case] value: &str, #[case] expected: &str) {
        let found = check(&response_with(Some(value)), 3600).expect("a finding");
        assert_eq!(found.message, expected);
    }

    #[test]
    fn a_message_with_no_keep_alive_is_not_read() {
        assert!(check(&response_with(None), 3600).is_none());
    }

    /// The field's own requirement, and the reason the negative cases above all
    /// carry a `Connection`.
    #[test]
    fn the_connection_token_must_travel_with_the_field() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("keep-alive", "timeout=30")],
        );
        let found = check(&tx, 3600).expect("a Keep-Alive with no connection option is reported");
        assert!(
            found.message.contains("connection option"),
            "{}",
            found.message
        );
    }

    /// The option is a field name, so the comparison folds case, and it is one
    /// member of a list rather than the whole value.
    #[rstest]
    #[case("Keep-Alive")]
    #[case("close, keep-alive")]
    #[case("keep-alive , upgrade")]
    fn the_connection_option_is_read_as_a_list_member(#[case] connection: &str) {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("connection", connection), ("keep-alive", "timeout=30")],
        );
        assert!(check(&tx, 3600).is_none(), "for {connection:?}");
    }

    /// Demanding the connection option of a version that forbids the field
    /// would be advice to violate a different document.
    #[rstest]
    #[case("HTTP/2.0")]
    #[case("HTTP/3.0")]
    fn the_connection_option_is_not_asked_of_http2_or_http3(#[case] version: &str) {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("keep-alive", "timeout=30")],
        );
        tx.response.as_mut().unwrap().version = version.into();
        assert!(check(&tx, 3600).is_none(), "for {version}");
    }

    /// The request half of the field, which the rule this one replaced could not
    /// reach: `server_keep_alive_timeout_reasonable` read the response only.
    #[test]
    fn the_request_section_is_judged_too() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("connection", "keep-alive"),
            ("keep-alive", "timeout=bad"),
        ]);
        let found = check(&tx, 3600).expect("a malformed request timeout is reported");
        assert!(found.message.starts_with("Request "), "{}", found.message);
    }

    /// The lines of one section are one list. Two field lines each holding half
    /// of a quoted-string are one well-formed member; read one at a time they
    /// are two unterminated ones.
    #[test]
    fn the_field_lines_of_a_section_are_one_list() {
        use hyper::header::HeaderValue;
        let mut tx = response_with(None);
        let headers = &mut tx.response.as_mut().unwrap().headers;
        headers.append(
            "keep-alive",
            HeaderValue::from_static("timeout=30, note=\"a"),
        );
        headers.append("keep-alive", HeaderValue::from_static(" b\""));
        assert!(check(&tx, 3600).is_none(), "{:?}", check(&tx, 3600));
    }

    /// `obs-text` is what a `to_str` reader folds into "this message has no
    /// `Keep-Alive`", and HTAB is `LWS` the grammar admits. Both reach the
    /// checks that own them here: the octet is a finding inside a `token` and
    /// data inside a `quoted-string`.
    #[test]
    fn an_octet_above_us_ascii_reaches_the_production_that_excludes_it() {
        let found = check(&response_with_raw(b"note=caf\xe9"), 3600)
            .expect("obs-text in a token is a finding");
        assert!(found.message.contains("0xE9"), "{}", found.message);

        let quoted = check(&response_with_raw(b"note=\"caf\xe9\""), 3600);
        assert!(quoted.is_none(), "obs-text is qdtext: {quoted:?}");

        let tab = check(&response_with_raw(b"timeout=\t30"), 3600);
        assert!(tab.is_none(), "HTAB is LWS: {tab:?}");
    }

    /// The rule reads RFC 2068's `token` with RFC 9110's `tchar` helper, on the
    /// claim that the two productions admit the same characters. That claim is
    /// what licenses not writing a second copy of the character class, and
    /// nothing else in the tree checks it — so it is checked here, over every
    /// octet, rather than asserted in a comment.
    #[test]
    fn rfc_2068s_token_and_rfc_9110s_tchar_are_the_same_character_class() {
        // `token = 1*<any CHAR except CTLs or tspecials>`: CHAR is US-ASCII, so
        // every octet at or above %x80 is out, and CTL takes %x00-1F and %x7F.
        const TSPECIALS: &str = "()<>@,;:\\\"/[]?={} \t";
        for b in 0u16..=0xff {
            let c = b as u8 as char;
            let is_token_char = (0x21..0x7f).contains(&b) && !TSPECIALS.contains(c);
            assert_eq!(
                crate::helpers::token::is_tchar(c),
                is_token_char,
                "{c:?} ({b:#04X}) is judged differently by the two productions"
            );
        }
    }

    /// A `HeaderValue` has to be able to carry the octets this rule reports on,
    /// or the findings above are unreachable. The dependency owns that boundary.
    #[test]
    fn a_header_value_carries_the_octets_this_rule_measures() {
        use hyper::header::HeaderValue;
        assert!(
            HeaderValue::from_bytes(b"note=caf\xe9").is_ok(),
            "obs-text is field content, and a capture has to be able to hold it"
        );
        assert!(
            HeaderValue::from_bytes(b"timeout=\t30").is_ok(),
            "HTAB is LWS, and it must reach the trim rather than the reader"
        );
    }

    #[test]
    fn id_and_scope() {
        let rule = MessageKeepAliveHeaderValidity;
        assert_eq!(rule.id(), "message_keep_alive_header_validity");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[rstest]
    #[case(None)]
    #[case(Some(0))]
    #[case(Some(-1))]
    fn validate_requires_a_positive_max_timeout(#[case] max: Option<i64>) {
        let cfg = cfg_with_optional_max(max);
        assert!(MessageKeepAliveHeaderValidity.validate(&cfg).is_err());
        assert!(crate::rules::validate_rules(&cfg).is_err());
    }

    /// A configuration this rule cannot read stops the whole rule, so a mistake
    /// in it cannot read as a clean run of the grammar checks.
    #[test]
    fn an_unreadable_config_reports_nothing_at_all() {
        assert!(MessageKeepAliveHeaderValidity
            .check_transaction(
                &response_with(Some("timeout=bad")),
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg_with_optional_max(None),
            )
            .is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        crate::rules::validate_rules(&cfg_with_max(3600))?;
        Ok(())
    }

    /// Nothing runs a rule's own `examples()` through the engine, so a
    /// `Compliant` value the rule rejects is published as guidance.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::Compliance;
        let mut saw_a_finding = false;
        for ex in MessageKeepAliveHeaderValidity.examples() {
            let mut lines = ex.snippet.lines();
            let start = lines.next().expect("an example has a start line");
            assert!(
                start.starts_with("HTTP/"),
                "this guard files an example's fields onto the response: {start:?}"
            );
            let fields: Vec<(&str, &str)> = lines
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"))
                })
                .collect();
            let tx = crate::test_helpers::make_test_transaction_with_response(200, &fields);
            let found = check(&tx, 3600);
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
