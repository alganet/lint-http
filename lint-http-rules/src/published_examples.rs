// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Every example a rule publishes is run through that rule, and the verdict
//! has to be the one the label makes.
//!
//! An `Example` is a claim: *this message conforms* or *this message draws a
//! finding*. The claim is rendered into the documentation and into `rules
//! list`, and until this module existed nothing checked it — five rules ran
//! their own examples, 190 did not. The first run over all of them found
//! examples describing an entry the rule had stopped reporting, examples that
//! contradicted the rule's own reasoning, exchanges shown one side at a time,
//! and a config example that did not name the value its non-compliant example
//! used. This gate is what keeps a repair to a rule from leaving its examples
//! behind.
//!
//! **What a snippet may look like.** The examples were written by hand in
//! several shapes, and the tokenizer here reads all of them: a request line
//! or a status line opening a message, header lines under it, a blank line
//! and then content; HTTP/2 and HTTP/3 pseudo-header fields; a curl-style
//! trace with `> ` and `< ` prefixes; a status line written as `200 OK`
//! alone; and a bare block of header lines with no start line, which is
//! placed on the side the field names it carries belong to. A full-line `#`
//! or `//` comment, and an inline `  # note` after a value, are documentation
//! and are not part of the message.
//!
//! **What a story is.** Several messages with a response among them are one
//! exchange after another, judged on the last one with the earlier ones as its
//! history; a run of requests alone is a list of alternatives, each judged on
//! its own. Two conventions carry what a story cannot say in fields: a comment
//! naming a delay (`# thirty seconds later`, `# after 120s`) spaces the next
//! message from the one before it, and a comment naming *another client* has
//! the next message sent by a second identity. A pseudo-header snippet is an
//! HTTP/2 message unless its label says `HTTP/3`.
//!
//! **A block whose every line names one field is that field's alternative
//! values**, and each of them is judged as a message of its own: `Cache-Control:
//! max-age=3600` beside `Cache-Control: no-cache` is two policies a sender might
//! write, not one message carrying both. So a non-compliant block of them has to
//! draw on every line rather than on some line, which is what found the
//! `Content-Disposition` example whose first value was conforming.
//!
//! **What is not judged, counted so it cannot grow unnoticed.** A field name the
//! header map refuses cannot be built at all, and the rules that show one build
//! it as octets in their own tests. It is skipped by shape, never by rule name,
//! and the count is asserted below.

use crate::http_transaction::{HttpTransaction, ResponseInfo};
use crate::rules::{Compliance, Rule};
use bytes::Bytes;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};

/// Fields a snippet writes only on a request.
const REQUEST_ONLY: &[&str] = &[
    "host",
    "accept",
    "accept-language",
    "accept-encoding",
    "accept-charset",
    "authorization",
    "proxy-authorization",
    "user-agent",
    "if-match",
    "if-none-match",
    "if-modified-since",
    "if-unmodified-since",
    "if-range",
    "range",
    "te",
    "expect",
    "origin",
    "referer",
    "cookie",
    "early-data",
    "upgrade-insecure-requests",
    "max-forwards",
    "from",
    "sec-fetch-user",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "sec-purpose",
    "want-digest",
    "want-repr-digest",
    "want-content-digest",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "sec-websocket-key",
    "sec-websocket-version",
    "prefer",
    "a-im",
    "access-control-request-method",
    "access-control-request-headers",
    "sec-ch-ua",
    "sec-ch-ua-platform",
    "sec-ch-ua-mobile",
    "dnt",
    "sec-gpc",
    "service-worker",
    "purpose",
];

/// Fields a snippet writes only on a response.
const RESPONSE_ONLY: &[&str] = &[
    "www-authenticate",
    "proxy-authenticate",
    "set-cookie",
    "content-disposition",
    "alt-svc",
    "strict-transport-security",
    "vary",
    "server-timing",
    "content-security-policy",
    "content-security-policy-report-only",
    "cache-status",
    "proxy-status",
    "accept-ch",
    "age",
    "etag",
    "location",
    "retry-after",
    "server",
    "accept-ranges",
    "accept-patch",
    "accept-post",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "origin-agent-cluster",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "access-control-max-age",
    "timing-allow-origin",
    "sunset",
    "deprecation",
    "link",
    "content-location",
    "expires",
    "last-modified",
    "authentication-info",
    "proxy-authentication-info",
    "sec-websocket-accept",
    "clear-site-data",
    "nel",
    "report-to",
    "reporting-endpoints",
    "x-robots-tag",
    "priority",
    "cdn-cache-control",
    "surrogate-control",
    "refresh",
];

/// Where a bare header block goes.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Placement {
    Request,
    Response,
    Either,
}

fn placement_of(names: &[String], needs_response: bool) -> Placement {
    let req = names.iter().any(|n| REQUEST_ONLY.contains(&n.as_str()));
    let resp = names.iter().any(|n| RESPONSE_ONLY.contains(&n.as_str()));
    match (req, resp) {
        (true, false) => Placement::Request,
        (false, true) => Placement::Response,
        (true, true) => Placement::Either,
        (false, false) if needs_response => Placement::Response,
        (false, false) => Placement::Either,
    }
}

/// The version string the transaction model records: the two specifications
/// that have no start-line write the minor digit, and so does a capture.
// cite(RFC 9113 § 8.3.1): "All HTTP/2 requests implicitly have a protocol version of "2.0""
// cite(RFC 9114 § 4.3.1): "HTTP/3 requests implicitly have a protocol version of "3.0"."
fn map_version(v: &str) -> String {
    match v {
        "HTTP/2" => "HTTP/2.0".into(),
        "HTTP/3" => "HTTP/3.0".into(),
        other => other.to_string(),
    }
}

fn strip_trace(line: &str) -> &str {
    if line == ">" || line == "<" {
        return "";
    }
    line.strip_prefix("> ")
        .or_else(|| line.strip_prefix("< "))
        .unwrap_or(line)
}

/// A request-line, and the target inside it.
///
/// The target is everything between the method and the version, joined back
/// with the spaces it was split on -- because `request-target` is where a
/// space is the defect. § 3.2 says no whitespace is allowed there and spends
/// its next sentence on why the value arrives anyway, and an example format
/// that reads a request-line as exactly three space-separated parts cannot
/// write the one message that sentence is about. Such a line was not a
/// request-line at all, so a snippet holding one tokenized to nothing and the
/// example was skipped with `NoMessageShape`.
///
/// The three guards on the method are what keep the wider shape from swallowing
/// its neighbours: a status line's first word is digits, a pseudo-header's and
/// a field line's carry the colon, and the version has to be last -- so
/// `HTTP/1.1 404 Not Found` is still a status line, whose own last word is not
/// a version.
fn request_line_parts(l: &str) -> Option<(&str, String, &str)> {
    let parts: Vec<&str> = l.split(' ').collect();
    let (method, version) = (parts.first()?, parts.last()?);
    if parts.len() < 3
        || method.is_empty()
        || method.chars().all(|c| c.is_ascii_digit())
        || method.contains(':')
        || !version.to_ascii_uppercase().starts_with("HTTP/")
    {
        return None;
    }
    Some((method, parts[1..parts.len() - 1].join(" "), version))
}

fn is_request_line(l: &str) -> bool {
    request_line_parts(l).is_some()
}

/// `HTTP/1.1 200 OK`, `HTTP/2 200`, or the trace shorthand `200 OK`.
fn parse_status_line(l: &str) -> Option<(String, u16)> {
    let mut it = l.split(' ');
    let first = it.next()?;
    if first.to_ascii_uppercase().starts_with("HTTP/") {
        let code: u16 = it.next()?.parse().ok()?;
        return Some((map_version(first), code));
    }
    if first.len() == 3 && first.chars().all(|c| c.is_ascii_digit()) {
        let code: u16 = first.parse().ok()?;
        return Some(("HTTP/1.1".into(), code));
    }
    None
}

fn is_header_line(l: &str) -> bool {
    match l.split_once(':') {
        Some((n, _)) => !n.is_empty() && !n.contains(' '),
        None => false,
    }
}

fn header_name_of(l: &str) -> String {
    l.split(':')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// The value without the inline `  # note` a snippet may put after it.
fn value_without_note(v: &str) -> &str {
    let v = match v.find(" #") {
        Some(i) if v[..i].ends_with(' ') || v[i + 2..].starts_with(' ') => &v[..i],
        _ => v,
    };
    v.trim_end_matches(' ').trim_start_matches(' ')
}

fn parse_headers(lines: &[String]) -> Result<HeaderMap, String> {
    let mut hm = HeaderMap::new();
    for l in lines {
        let (n, v) = l
            .split_once(':')
            .ok_or_else(|| format!("not a header line: {l:?}"))?;
        let name = HeaderName::from_bytes(n.as_bytes()).map_err(|e| format!("{n:?}: {e}"))?;
        let value = HeaderValue::from_bytes(value_without_note(v).as_bytes())
            .map_err(|e| format!("{v:?}: {e}"))?;
        hm.append(name, value);
    }
    Ok(hm)
}

/// `...500 bytes...`, `<chunked body>`, `(body)`: a stand-in for content the
/// example does not spell out, which is no content at all.
fn is_placeholder_body(body: &str) -> bool {
    let t = body.trim();
    let bracketed = |open: char, close: char| {
        t.starts_with(open) && t.ends_with(close) && !t.contains('\n') && !t.starts_with("<html")
    };
    t.starts_with("...") || t.starts_with('…') || bracketed('<', '>') || bracketed('(', ')')
}

/// One message as the snippet wrote it.
#[derive(Debug, Default, Clone)]
struct Msg {
    is_response: bool,
    method: String,
    target: String,
    version: String,
    status: u16,
    pseudo: Vec<(String, String)>,
    headers: Vec<String>,
    body: Vec<String>,
    /// Seconds after the previous message, when a comment before it said so.
    delay: Option<i64>,
    /// Sent by a second client, when a comment before it said so.
    other_client: bool,
}

/// `# thirty seconds later`, `# after 120s`, `# 5 minutes later`.
fn delay_in_comment(line: &str) -> Option<i64> {
    let l = line.to_ascii_lowercase();
    if !(l.contains("later") || l.contains("after")) {
        return None;
    }
    let words: Vec<&str> = l
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    words
        .iter()
        .enumerate()
        .find_map(|(i, w)| delay_at(&words, i, w))
}

fn delay_at(words: &[&str], i: usize, w: &str) -> Option<i64> {
    let digits: String = w.chars().take_while(|c| c.is_ascii_digit()).collect();
    let (num, unit) = if !digits.is_empty() && digits.len() < w.len() {
        (digits.parse::<i64>().ok(), &w[digits.len()..])
    } else {
        (number_word(w), words.get(i + 1).copied().unwrap_or(""))
    };
    let n = num?;
    let mult = match unit.chars().next()? {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        _ => return None,
    };
    Some(n * mult)
}

fn number_word(w: &str) -> Option<i64> {
    match w.parse::<i64>() {
        Ok(n) => Some(n),
        Err(_) => match w {
            "one" | "a" | "an" => Some(1),
            "two" => Some(2),
            "five" => Some(5),
            "ten" => Some(10),
            "thirty" => Some(30),
            "sixty" => Some(60),
            _ => None,
        },
    }
}

/// A comment naming another client switches the identity of what follows.
fn other_client_in_comment(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    l.contains("another client") || l.contains("different client") || l.contains("client b")
}

/// Reads a snippet line by line into messages.
#[derive(Default)]
struct Tokenizer {
    msgs: Vec<Msg>,
    cur: Option<Msg>,
    in_body: bool,
    pending_delay: Option<i64>,
    other_client: bool,
}

impl Tokenizer {
    fn finish_current(&mut self) {
        if let Some(m) = self.cur.take() {
            self.msgs.push(m);
        }
    }

    fn comment(&mut self, line: &str) {
        if let Some(d) = delay_in_comment(line) {
            self.pending_delay = Some(d);
        }
        if other_client_in_comment(line) {
            self.other_client = true;
        }
    }

    fn start(&mut self, msg: Msg) {
        self.finish_current();
        self.cur = Some(Msg {
            delay: self.pending_delay.take(),
            other_client: self.other_client,
            ..msg
        });
        self.in_body = false;
    }

    /// A start line ends a body; anything else in a body is content.
    fn body_line(&mut self, line: &str) -> bool {
        if !self.in_body || self.cur.is_none() {
            return false;
        }
        if is_request_line(line) || parse_status_line(line).is_some() {
            self.in_body = false;
            return false;
        }
        self.cur
            .as_mut()
            .expect("a message is open")
            .body
            .push(line.to_string());
        true
    }

    fn pseudo(&mut self, line: &str) -> Option<()> {
        let (n, v) = line[1..].split_once(':')?;
        let m = self.cur.get_or_insert_with(|| Msg {
            version: "HTTP/2.0".into(),
            ..Default::default()
        });
        if n == "status" {
            m.is_response = true;
            m.status = v.trim().parse().ok()?;
        }
        m.pseudo.push((n.to_string(), v.trim().to_string()));
        Some(())
    }

    fn header(&mut self, line: &str) {
        let m = self.cur.get_or_insert_with(|| Msg {
            version: "HTTP/1.1".into(),
            ..Default::default()
        });
        m.headers.push(line.to_string());
    }

    /// `None` when the line is nothing a message can hold.
    fn line(&mut self, raw: &str) -> Option<()> {
        let line = strip_trace(raw.trim_end_matches('\r'));
        if line.starts_with('#') || line.starts_with("//") {
            self.comment(line);
            return Some(());
        }
        if self.body_line(line) {
            return Some(());
        }
        if line.trim().is_empty() {
            self.in_body = self.cur.is_some();
            return Some(());
        }
        if let Some((method, target, version)) = request_line_parts(line) {
            self.start(Msg {
                method: method.to_string(),
                target,
                version: map_version(version),
                ..Default::default()
            });
            return Some(());
        }
        if let Some((version, status)) = parse_status_line(line) {
            self.start(Msg {
                is_response: true,
                version,
                status,
                ..Default::default()
            });
            return Some(());
        }
        if line.starts_with(':') {
            return self.pseudo(line);
        }
        if is_header_line(line) {
            self.header(line);
            return Some(());
        }
        None
    }
}

/// The messages a snippet holds, or `None` when it has no message shape.
fn tokenize(snippet: &str) -> Option<Vec<Msg>> {
    let mut t = Tokenizer::default();
    for raw in snippet.lines() {
        t.line(raw)?;
    }
    t.finish_current();
    if t.msgs.is_empty() {
        None
    } else {
        Some(t.msgs)
    }
}

fn fresh_tx() -> HttpTransaction {
    let mut tx = HttpTransaction::new(
        crate::test_helpers::make_test_client(),
        "GET".into(),
        "http://example/".into(),
    );
    tx.request.headers = HeaderMap::new();
    tx
}

struct Content {
    length: Option<u64>,
    bytes: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

fn content_of(lines: &[String]) -> Result<Content, String> {
    let none = Content {
        length: None,
        bytes: None,
        trailers: None,
    };
    let text = lines.join("\n");
    let text = text.trim_end_matches('\n').to_string();
    if text.trim().is_empty() {
        return Ok(none);
    }
    // A chunked-body placeholder followed by field lines: those are trailers.
    if lines.len() > 1
        && is_placeholder_body(&lines[0])
        && lines[1..].iter().all(|l| is_header_line(l))
    {
        return Ok(Content {
            trailers: Some(parse_headers(&lines[1..])?),
            ..none
        });
    }
    if is_placeholder_body(&text) {
        return Ok(none);
    }
    Ok(Content {
        length: Some(text.len() as u64),
        bytes: Some(Bytes::from(text)),
        trailers: None,
    })
}

/// The target a capture records for pseudo-header control data: the URI the
/// transport reassembles, or `*` for the asterisk form.
fn reassembled_target(pseudo: &[(String, String)]) -> Result<String, String> {
    let get = |k: &str| -> Result<Option<String>, String> {
        let mut found = pseudo
            .iter()
            .filter(|(n, _)| n == k)
            .map(|(_, v)| v.clone());
        let first = found.next();
        if found.next().is_some() {
            return Err(format!("repeated :{k}"));
        }
        Ok(first)
    };
    let (scheme, authority, path) = (get("scheme")?, get("authority")?, get("path")?);
    Ok(match (scheme, authority, path) {
        (_, _, Some(p)) if p == "*" => "*".into(),
        (Some(s), Some(a), Some(p)) => format!("{s}://{a}{p}"),
        (Some(s), Some(a), None) => format!("{s}://{a}"),
        (_, _, Some(p)) => p,
        (_, Some(a), None) => a,
        _ => String::new(),
    })
}

fn fill_request(tx: &mut HttpTransaction, m: &Msg) -> Result<(), String> {
    if m.pseudo.is_empty() {
        tx.request.method = m.method.clone();
        tx.request.uri = m.target.clone();
    } else {
        let method = m
            .pseudo
            .iter()
            .find(|(n, _)| n == "method")
            .map(|(_, v)| v.clone());
        tx.request.method = method.unwrap_or_else(|| "GET".into());
        tx.request.uri = reassembled_target(&m.pseudo)?;
    }
    tx.request.version = m.version.clone();
    tx.request.headers = parse_headers(&m.headers)?;
    let content = content_of(&m.body)?;
    tx.request.body_length = content.length;
    tx.request_body = content.bytes;
    tx.request.trailers = content.trailers;
    Ok(())
}

fn fill_response(tx: &mut HttpTransaction, m: &Msg) -> Result<(), String> {
    let headers = parse_headers(&m.headers)?;
    let content = content_of(&m.body)?;
    tx.response_body = content.bytes;
    tx.response = Some(ResponseInfo {
        status: m.status,
        version: m.version.clone(),
        headers,
        body_length: content.length,
        body_interrupted: false,
        trailers: content.trailers,
    });
    Ok(())
}

fn second_client() -> lint_http_core::state::ClientIdentifier {
    lint_http_core::state::ClientIdentifier::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
        "other-agent".to_string(),
    )
}

/// Groups messages into transactions: a request and the final response after
/// it are one; a lone response is one; a lone request is one. Timestamps
/// advance by the delays the comments named, one second otherwise.
fn group(msgs: &[Msg]) -> Result<Vec<HttpTransaction>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut clock: i64 = 0;
    let base = chrono::Utc::now() - chrono::Duration::days(1);
    while i < msgs.len() {
        let mut tx = fresh_tx();
        clock += msgs[i].delay.unwrap_or(1);
        tx.timestamp = base + chrono::Duration::seconds(clock);
        if msgs[i].other_client {
            tx.client = second_client();
        }
        if msgs[i].is_response {
            fill_response(&mut tx, &msgs[i])?;
            i += 1;
        } else {
            fill_request(&mut tx, &msgs[i])?;
            i += 1;
            // Interim responses are read past; the final one is the answer.
            while i < msgs.len() && msgs[i].is_response {
                clock += msgs[i].delay.unwrap_or(0);
                fill_response(&mut tx, &msgs[i])?;
                i += 1;
                if msgs[i - 1].status >= 200 {
                    break;
                }
            }
        }
        out.push(tx);
    }
    Ok(out)
}

/// The rule's own config example, enabled, is the configuration its examples
/// are documented beside.
fn rule_config(rule: &dyn Rule) -> crate::config::Config {
    let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
    if let Ok(mut t) = rule.config_example().parse::<toml::Table>() {
        t.insert("enabled".into(), toml::Value::Boolean(true));
        cfg.rules
            .insert(rule.id().to_string(), toml::Value::Table(t));
    }
    cfg
}

fn ids_of(found: Vec<crate::lint::Violation>) -> Vec<String> {
    found.into_iter().map(|v| v.violation).collect()
}

fn judge_one(rule: &dyn Rule, cfg: &crate::config::Config, tx: &HttpTransaction) -> Vec<String> {
    ids_of(crate::test_helpers::run_rule_all(
        rule,
        tx,
        &crate::transaction_history::TransactionHistory::empty(),
        cfg,
    ))
}

/// The last transaction judged with the earlier ones as its history, all on
/// one connection.
fn judge_story(
    rule: &dyn Rule,
    cfg: &crate::config::Config,
    mut txs: Vec<HttpTransaction>,
) -> Vec<String> {
    let conn = uuid::Uuid::new_v4();
    for t in txs.iter_mut() {
        t.connection_id = Some(conn);
    }
    let last = txs.pop().expect("a story has a last exchange");
    // History is newest-first; the group stamped the timestamps increasing.
    txs.reverse();
    let history = crate::transaction_history::TransactionHistory::from_transactions(txs);
    ids_of(crate::test_helpers::run_rule_all(
        rule, &last, &history, cfg,
    ))
}

/// Why a snippet was not judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Skipped {
    /// Nothing in it is a message.
    NoMessageShape,
    /// A name or value the header map refuses.
    Unbuildable,
    /// A block with no start line that also carries content. A blank line
    /// after a field line opens content, so everything under it is body: on a
    /// block of alternative values, written one per line, the blank lines make
    /// all but the first of them body and nothing judges them. Twice this
    /// silently unjudged the very value an example was written for, so it is
    /// named rather than judged on whatever the first line happened to draw.
    BareBlockWithContent,
}

/// The findings each judged message drew; one entry per message judged.
type Verdicts = Vec<Vec<String>>;

/// A bare header block, placed on the side its names belong to; a block
/// naming both sides is two messages, one each way.
fn judge_bare(
    rule: &dyn Rule,
    cfg: &crate::config::Config,
    msgs: &[Msg],
) -> Result<Verdicts, Skipped> {
    let names: Vec<String> = msgs
        .iter()
        .flat_map(|m| m.headers.iter())
        .map(|l| header_name_of(l))
        .collect();
    // A block whose every line names one field is a list of that field's
    // alternative values, and the label speaks of each of them: `Cache-Control:
    // max-age=3600` beside `Cache-Control: no-cache` is two policies a sender
    // might write, not one message carrying both. So each line is judged as its
    // own message, and a `NonCompliant` block has to draw on every one of them.
    // Read as a single message instead, the block asserts only that *something*
    // in it is wrong, and the line that is right rides in unexamined.
    let alternatives = names.len() > 1 && names.iter().all(|n| n == &names[0]);
    let owned: Vec<Msg>;
    let msgs: &[Msg] = if alternatives {
        owned = msgs
            .iter()
            .flat_map(|m| m.headers.iter())
            .map(|line| Msg {
                headers: vec![line.clone()],
                body: Vec::new(),
                ..Default::default()
            })
            .collect();
        &owned
    } else {
        msgs
    };
    let placement = placement_of(&names, rule.needs_response());
    let mut out = Vec::new();
    for m in msgs {
        let mut fired = Vec::new();
        for (as_response, lines) in bare_variants(m, placement, rule.needs_response()) {
            let mut mm = m.clone();
            mm.headers = lines;
            let mut tx = fresh_tx();
            let built = if as_response {
                mm.is_response = true;
                mm.status = 200;
                mm.version = "HTTP/1.1".into();
                fill_response(&mut tx, &mm)
            } else {
                mm.method = "GET".into();
                mm.target = "/".into();
                mm.version = "HTTP/1.1".into();
                fill_request(&mut tx, &mm)
            };
            built.map_err(|_| Skipped::Unbuildable)?;
            fired.extend(judge_one(rule, cfg, &tx));
        }
        out.push(fired);
    }
    Ok(out)
}

/// `(as_response, header lines)` for each side a bare block is judged on.
fn bare_variants(m: &Msg, placement: Placement, needs_response: bool) -> Vec<(bool, Vec<String>)> {
    let names: Vec<String> = m.headers.iter().map(|l| header_name_of(l)).collect();
    let p = match placement {
        Placement::Either => placement_of(&names, needs_response),
        p => p,
    };
    match p {
        Placement::Request => vec![(false, m.headers.clone())],
        Placement::Response => vec![(true, m.headers.clone())],
        Placement::Either => {
            let not_in = |set: &[&str]| -> Vec<String> {
                m.headers
                    .iter()
                    .filter(|l| !set.contains(&header_name_of(l).as_str()))
                    .cloned()
                    .collect()
            };
            [(false, not_in(RESPONSE_ONLY)), (true, not_in(REQUEST_ONLY))]
                .into_iter()
                .filter(|(_, lines)| !lines.is_empty())
                .collect()
        }
    }
}

/// Everything a rule's example is judged as.
fn judge(rule: &dyn Rule, ex: &crate::rules::Example) -> Result<Verdicts, Skipped> {
    let cfg = rule_config(rule);
    let mut msgs = tokenize(ex.snippet).ok_or(Skipped::NoMessageShape)?;
    if ex.label.is_some_and(|l| l.contains("HTTP/3")) {
        for m in msgs.iter_mut().filter(|m| !m.pseudo.is_empty()) {
            m.version = "HTTP/3.0".into();
        }
    }
    let bare = msgs
        .iter()
        .all(|m| !m.is_response && m.method.is_empty() && m.pseudo.is_empty());
    if bare {
        if msgs
            .iter()
            .any(|m| m.body.iter().any(|l| !l.trim().is_empty()))
        {
            return Err(Skipped::BareBlockWithContent);
        }
        return judge_bare(rule, &cfg, &msgs);
    }
    let txs = group(&msgs).map_err(|_| Skipped::Unbuildable)?;
    // Several messages with a response among them are one story; a run of
    // requests alone is a list of alternatives.
    if msgs.len() > 1 && msgs.iter().any(|m| m.is_response) {
        return Ok(vec![judge_story(rule, &cfg, txs)]);
    }
    Ok(txs.iter().map(|tx| judge_one(rule, &cfg, tx)).collect())
}

/// A compliant example draws nothing on any message; a non-compliant one
/// draws a finding on every message it lists, or on the story's last exchange.
fn as_labelled(compliance: Compliance, verdicts: &Verdicts) -> bool {
    match compliance {
        Compliance::Compliant => verdicts.iter().all(|v| v.is_empty()),
        Compliance::NonCompliant => verdicts.iter().all(|v| !v.is_empty()),
    }
}

/// The entries no published example demonstrates.
///
/// A non-compliant example is judged only on whether it drew *something*, and
/// a rule reports several entries, so an example goes on passing while the
/// entry it was written for stops being reported: a sibling on the same value
/// answers first and the verdict is not empty. Nothing said which entry was
/// demonstrated, so nothing noticed when one stopped being.
///
/// This names it from the other side. Every entry a non-compliant example
/// draws is demonstrated; the rest are listed here, and the list is exact.
/// An entry that loses its last demonstration appears in it and the assertion
/// below says so by name; an entry that gains one leaves it, and the same
/// assertion asks for the row to go.
///
/// A row here is a catalogue entry whose documentation shows no instance of
/// the traffic it flags. It is a work list, not a permission: shrinking it is
/// the point, and it may not grow silently.
const WITHOUT_EXAMPLE: &[&str] = &[
    "access_control_allow_credentials_invalid",
    "access_control_allow_origin_empty",
    "alpn_protocol_name_length_invalid",
    "alt_svc_authority_character_forbidden",
    "alt_svc_parameter_empty",
    "alt_svc_parameter_equals_missing",
    "alt_svc_parameter_value_empty",
    "alt_svc_port_empty",
    "alt_svc_port_invalid",
    "auth_param_equals_missing",
    "authority_tunnel_host_empty",
    "base64_character_forbidden",
    "base64_pad_bits_invalid",
    "base64_quantum_malformed",
    "basic_credentials_control_character_forbidden",
    "boundary_character_forbidden",
    "cache_control_no_cache_argument_empty",
    "cache_control_private_argument_empty",
    "challenge_member_empty",
    "challenge_parameter_name_character_forbidden",
    "challenge_parameter_name_empty",
    "challenge_parameter_value_character_forbidden",
    "challenge_parameter_value_missing",
    "charset_empty",
    "comment_character_forbidden",
    "conditional_date_conflicting",
    "conditional_empty",
    "content_coding_identity_forbidden",
    "content_coding_wildcard_forbidden",
    "content_disposition_name_empty",
    "content_length_numeral_invalid",
    "content_location_empty",
    "content_range_complete_length_conflicting",
    "content_range_empty",
    "content_range_incl_range_malformed",
    "content_range_length_conflicting",
    "content_range_numeral_invalid",
    "content_range_numeral_malformed",
    "content_range_positions_conflicting",
    "content_range_slash_missing",
    "content_range_spec_missing",
    "content_range_spec_whitespace_forbidden",
    "content_range_unit_malformed",
    "content_range_unsatisfied_range_malformed",
    "content_security_policy_base64_value_empty",
    "content_security_policy_base64_value_malformed",
    "content_security_policy_directive_empty",
    "content_security_policy_source_empty",
    "cookie_domain_empty",
    "cookie_domain_ipv6_literal_forbidden",
    "cookie_expires_missing",
    "cookie_flag_value_forbidden",
    "cookie_max_age_missing",
    "cookie_pair_missing",
    "cookie_path_control_character_forbidden",
    "cookie_path_empty",
    "cookie_path_missing",
    "cookie_same_site_missing",
    "credentials_control_character_forbidden",
    "credentials_empty",
    "delta_seconds_empty",
    "digest_credentials_nc_malformed",
    "digest_credentials_parameter_empty",
    "digest_equals_missing",
    "digest_field_obsolete",
    "digest_member_empty",
    "digest_preference_invalid",
    "digest_preference_malformed",
    "digest_value_empty",
    "domain_label_edge_hyphen_forbidden",
    "domain_label_empty",
    "domain_label_length_invalid",
    "domain_name_length_invalid",
    "domain_name_whitespace_or_control_forbidden",
    "early_data_duplicated",
    "etag_character_forbidden",
    "etag_weak_indicator_invalid",
    "expect_100_continue_invalid",
    "expect_value_empty",
    "forwarded_element_whitespace_forbidden",
    "forwarded_pair_equals_missing",
    "forwarded_pair_value_empty",
    "forwarded_response_forbidden",
    "http_date_empty",
    "http_date_whitespace_forbidden",
    "if_range_empty",
    "keep_alive_parameter_name_missing",
    "keep_alive_parameter_value_empty",
    "language_tag_edge_hyphen_forbidden",
    "language_tag_empty",
    "language_tag_subtag_empty",
    "language_tag_whitespace_or_control_forbidden",
    "link_attribute_duplicated",
    "link_member_malformed",
    "link_param_empty",
    "link_param_value_empty",
    "link_rel_empty",
    "link_rel_malformed",
    "mailbox_angle_addr_missing",
    "mailbox_atom_empty",
    "mailbox_comment_character_forbidden",
    "mailbox_comment_terminator_missing",
    "mailbox_display_name_word_missing",
    "mailbox_domain_literal_character_forbidden",
    "mailbox_domain_literal_terminator_missing",
    "mailbox_empty",
    "mailbox_local_part_missing",
    "mailbox_quoted_pair_malformed",
    "mailbox_quoted_string_character_forbidden",
    "mailbox_quoted_string_terminator_missing",
    "mailbox_trailing_character_forbidden",
    "media_type_empty",
    "media_type_name_empty",
    "method_head_content_forbidden",
    "node_ipv6_address_malformed",
    "node_ipv6_brackets_missing",
    "node_ipv6_closing_bracket_missing",
    "node_ipv6_representation_invalid",
    "origin_agent_cluster_empty",
    "parameter_equals_whitespace_forbidden",
    "preference_applied_conflicting",
    "preference_applied_value_empty",
    "priority_incremental_malformed",
    "problem_details_empty",
    "quoted_pair_malformed",
    "quoted_string_control_character_forbidden",
    "quoted_string_quote_escape_missing",
    "range_equals_missing",
    "range_position_malformed",
    "range_spec_character_forbidden",
    "referer_empty",
    "refresh_url_empty",
    "refresh_url_malformed",
    "request_target_malformed",
    "sec_fetch_value_malformed",
    "sec_websocket_accept_missing",
    "sec_websocket_extensions_parameter_missing",
    "sec_websocket_extensions_parameter_value_empty",
    "sec_websocket_extensions_unsolicited",
    "sec_websocket_key_length_invalid",
    "sec_websocket_protocol_empty",
    "sec_websocket_version_empty",
    "sec_websocket_version_list_empty",
    "sec_websocket_version_missing",
    "server_timing_param_empty",
    "server_timing_param_value_empty",
    "status_101_forbidden",
    "status_206_multipart_forbidden",
    "status_304_metadata_forbidden",
    "status_416_unsolicited",
    "status_417_ignored",
    "status_trailers_forbidden",
    "strict_transport_security_directive_duplicated",
    "strict_transport_security_directive_value_missing",
    "strict_transport_security_empty",
    "structured_field_character_forbidden",
    "structured_field_empty",
    "structured_field_inner_list_malformed",
    "structured_field_member_empty",
    "structured_field_value_empty",
    "token68_body_empty",
    "token68_padding_malformed",
    "transfer_coding_parameter_missing",
    "upgrade_101_empty",
    "upgrade_101_invalid",
    "upgrade_101_missing",
    "uri_host_bracket_forbidden",
    "uri_host_closing_bracket_missing",
    "uri_host_ip_literal_malformed",
    "uri_scheme_empty",
    "via_comment_duplicated",
    "via_member_malformed",
    "warning_agent_missing",
    "warning_member_malformed",
    "warning_text_missing",
    "weight_equals_whitespace_forbidden",
    "x_content_type_options_invalid",
];

/// Every entry a non-compliant example draws, across the whole catalogue.
fn entries_demonstrated() -> std::collections::BTreeSet<String> {
    let mut drawn = std::collections::BTreeSet::new();
    for rule in crate::rules::REGISTERED_RULES.iter() {
        let rule: &dyn Rule = *rule;
        for ex in rule.examples() {
            if ex.compliance != Compliance::NonCompliant {
                continue;
            }
            if let Ok(verdicts) = judge(rule, ex) {
                drawn.extend(verdicts.into_iter().flatten());
            }
        }
    }
    drawn
}

#[test]
fn every_entry_without_an_example_is_named() {
    let drawn = entries_demonstrated();
    let mut defined: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for rule in crate::rules::REGISTERED_RULES.iter() {
        let rule: &dyn Rule = *rule;
        for def in rule.violations() {
            defined.insert(def.id);
        }
    }
    let undemonstrated: Vec<&str> = defined
        .iter()
        .copied()
        .filter(|id| !drawn.contains(*id))
        .collect();
    let listed: std::collections::BTreeSet<&str> = WITHOUT_EXAMPLE.iter().copied().collect();
    let measured: std::collections::BTreeSet<&str> = undemonstrated.iter().copied().collect();
    let gained: Vec<&&str> = measured.difference(&listed).collect();
    let lost: Vec<&&str> = listed.difference(&measured).collect();
    assert!(
        gained.is_empty(),
        "{} entries lost their last published example: {gained:?}",
        gained.len()
    );
    assert!(
        lost.is_empty(),
        "{} entries now have an example and may leave WITHOUT_EXAMPLE: {lost:?}",
        lost.len()
    );
    assert_eq!(
        listed.len(),
        WITHOUT_EXAMPLE.len(),
        "WITHOUT_EXAMPLE names an entry twice"
    );
}

#[test]
fn published_examples_are_judged_the_way_they_are_labelled() {
    use std::collections::BTreeMap;
    let mut skipped: BTreeMap<Skipped, Vec<String>> = BTreeMap::new();
    let mut mismatches: Vec<String> = Vec::new();
    let mut judged = 0usize;
    for rule in crate::rules::REGISTERED_RULES.iter() {
        let rule: &dyn Rule = *rule;
        for ex in rule.examples() {
            let label = ex.label.unwrap_or("");
            let first_line = ex.snippet.lines().next().unwrap_or("");
            match judge(rule, ex) {
                Err(why) => skipped
                    .entry(why)
                    .or_default()
                    .push(format!("{} {label} {first_line}", rule.id())),
                Ok(verdicts) => {
                    judged += 1;
                    if !as_labelled(ex.compliance, &verdicts) {
                        mismatches.push(format!(
                            "{} labelled {:?} {label}: {first_line:?} drew {verdicts:?}",
                            rule.id(),
                            ex.compliance
                        ));
                    }
                }
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} published examples are not judged the way they are labelled:\n  {}",
        mismatches.len(),
        mismatches.join("\n  ")
    );
    // The three shapes nothing here can judge, each pinned so a new example
    // landing in one of them is noticed rather than silently unjudged.
    let count = |k: Skipped| skipped.get(&k).map_or(0, Vec::len);
    assert_eq!(
        count(Skipped::NoMessageShape),
        0,
        "{:?}",
        skipped.get(&Skipped::NoMessageShape)
    );
    assert_eq!(
        count(Skipped::BareBlockWithContent),
        0,
        "{:?}",
        skipped.get(&Skipped::BareBlockWithContent)
    );
    assert_eq!(
        count(Skipped::Unbuildable),
        2,
        "{:?}",
        skipped.get(&Skipped::Unbuildable)
    );
    assert!(judged > 860, "{judged} examples judged");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_first_trace_line_is_not_a_request() {
        assert!(!is_request_line("401 Unauthorized HTTP/1.1"));
        assert_eq!(
            parse_status_line("401 Unauthorized HTTP/1.1"),
            Some(("HTTP/1.1".into(), 401))
        );
        assert!(is_request_line("G@T /index.html HTTP/1.1"));
    }

    /// The whitespace a request-target is not allowed to carry, which is the
    /// whole of what one entry is about and what the three-part reading could
    /// not express.
    #[test]
    fn a_target_keeps_the_whitespace_that_makes_it_a_finding() {
        assert_eq!(
            request_line_parts("GET /a path HTTP/1.1"),
            Some(("GET", "/a path".to_string(), "HTTP/1.1"))
        );
        assert_eq!(
            request_line_parts("GET  HTTP/1.1"),
            Some(("GET", String::new(), "HTTP/1.1"))
        );
        // The version is last, so a reason phrase carrying one is not a target.
        assert!(!is_request_line("HTTP/1.1 404 Not Found"));
    }

    #[test]
    fn comments_carry_time_and_identity() {
        assert_eq!(delay_in_comment("# thirty seconds later"), Some(30));
        assert_eq!(delay_in_comment("# revalidates after 120s"), Some(120));
        assert_eq!(delay_in_comment("# five minutes later"), Some(300));
        assert_eq!(delay_in_comment("# later, after expiry:"), None);
        assert!(other_client_in_comment("# later, a different client sends"));
    }

    #[test]
    fn an_inline_note_is_not_part_of_the_value() {
        assert_eq!(value_without_note(" ?1  # whitespace is trimmed"), "?1");
        assert_eq!(value_without_note(" a#b"), "a#b");
    }

    #[test]
    fn the_asterisk_form_reassembles_to_the_asterisk() {
        let pseudo = vec![
            ("scheme".to_string(), "https".to_string()),
            ("authority".to_string(), "example.com".to_string()),
            ("path".to_string(), "*".to_string()),
        ];
        assert_eq!(reassembled_target(&pseudo).unwrap(), "*");
    }
}
