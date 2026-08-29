// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{
    combined_field_value_as_written, is_nominated_by_connection, list_members, trim_ows,
};
use crate::helpers::shown::{describe_octet, shown_in_finding};
use crate::helpers::websocket::{
    compute_accept, opening_handshake_version, sec_websocket_key_defect,
};
use crate::lint::Violation;
use crate::rules::Rule;

/// The server's half of a WebSocket opening handshake, measured against the
/// request it answers.
///
/// `sec_websocket_headers_consistent` measures the request; this rule
/// measures what came back, and the two share the gate deciding which exchanges
/// are a handshake at all.
///
/// Only a 101 is measured, and that is the whole premise. RFC 6455 § 4.2.2 lists
/// what a server sends *if it chooses to accept the incoming connection*, and the
/// status is how a server states whether it did: the same section has it answering
/// 401, 3xx, 403, 404 and 426 in five named circumstances, and § 4.1 hands any of
/// them back to plain HTTP. So a non-101 answer to a handshake is not a defect in
/// one — it is a refusal, and the rest of the catalogue measures a refusal like
/// any other response.
///
/// The request is read only for what the response has to be derived from: the
/// `Sec-WebSocket-Key` behind `Sec-WebSocket-Accept`, and the subprotocols and
/// extensions the server may choose among. What is wrong with the *request* is the
/// other rule's finding, with one exception that is this rule's alone — a 101
/// completing a handshake the server was required to refuse, which no rule holding
/// one half of the exchange can see.
///
/// The history parameter is unused: both halves of a transaction arrive together,
/// and nothing here spans two of them.
pub struct WebsocketHandshakeValid;

impl WebsocketHandshakeValid {
    /// The one finding here that is about the request, and it is about the
    /// response's existence rather than about the request's fields.
    ///
    /// The section describing how a server reads a handshake opens by saying what
    /// a server does with one that does not match the description below it, and a
    /// 101 is the server having done the opposite. Item 5 of that description is
    /// the key, and what a well-formed one is is asked of the production's owner —
    /// the same reading `Sec-WebSocket-Accept` is derived through, so the exchange
    /// is judged from one reading of the key rather than two.
    ///
    /// `sec_websocket_headers_consistent` reports the same value, and the
    /// two findings are not duplicates: there the sender at fault is the client and
    /// the defect is the value; here it is the server, and the defect is that it
    /// completed the handshake anyway.
    ///
    /// The neighbouring item — `Sec-WebSocket-Version: 13` — is not asked, and the
    /// reason is that the same document answers it twice. This section's opening
    /// makes every item of its list a MUST-refuse; § 4.2.2's `/version/` says a
    /// server aborts if the version *"does not match a version understood by the
    /// server"*, which is a fact about the server rather than about the message,
    /// and a 101 is that server saying it understood. The more specific sentence
    /// governs the field it is about, so the disagreement is recorded rather than
    /// resolved by picking the stricter half.
    // cite(RFC 6455 § 4.2.1): "the server MUST stop processing the client's handshake and return an HTTP response with an appropriate error code (such as 400 Bad Request)"
    // cite(RFC 6455 § 4.2.1): "including but not limited to any violations of the ABNF grammar specified for the components of the handshake"
    // cite(RFC 6455 § 4.2.1): "A |Sec-WebSocket-Key| header field with a base64-encoded (see Section 4 of [RFC4648]) value that, when decoded, is 16 bytes in length."
    // cite(RFC 6455 § 4.2.1): "A |Sec-WebSocket-Version| header field, with a value of 13."
    // cite(RFC 6455 § 4.2.2): "If this version does not match a version understood by the server, the server MUST abort the WebSocket handshake described in this section and instead send an appropriate HTTP error code (such as 426 Upgrade Required) and a |Sec-WebSocket-Version| header field indicating the version(s) the server is capable of understanding."
    fn refusable_handshake(req_headers: &hyper::HeaderMap) -> Option<String> {
        let Some(raw) = combined_field_value_as_written(req_headers, "sec-websocket-key") else {
            return Some(
                "the request it answers carries no Sec-WebSocket-Key header field, and a \
                 handshake missing one is a handshake the server was required to refuse"
                    .into(),
            );
        };
        let defect = sec_websocket_key_defect(&raw)?;
        // The one verdict that is not this sentence's business, and it is the
        // document's own NOTE that makes the point: § 4.1 prints
        // `AQIDBAUGBwgJCgsMDQ4PEC==` as the field value for the octets 0x01 through
        // 0x10, and that spelling's last symbol carries bits a conforming encoder
        // zeroes. § 4.2.1 item 5 asks for a base64-encoded value that decodes to
        // sixteen bytes, which this is; `base64-value-non-empty` derives it; and
        // the sentence that refuses it is addressed to encoders, with the decoder
        // left a choice RFC 6455 does not exercise. A server that answered such a
        // handshake was owed no refusal. The value is still reported — against the
        // client, by the rule that reads the request, which is the party the
        // encoder sentence is about.
        if matches!(
            defect,
            crate::helpers::websocket::SecWebSocketKeyDefect::PadBits
        ) {
            return None;
        }
        Some(format!(
            "the request it answers offers the Sec-WebSocket-Key `{}`, which is not the nonce \
             that field is defined as ({defect}) — a handshake the server was required to refuse \
             rather than complete",
            shown_in_finding(trim_ows(&raw))
        ))
    }

    /// The response's `Upgrade`, and the quantifier is the whole of the question.
    ///
    /// The two directions of this field are one list item apart and they do not ask
    /// the same thing. The request's *"MUST include the "websocket" keyword"* — some
    /// member is `websocket`, which is what `sec_websocket_headers_consistent`
    /// asks. The response's has the client fail the connection when the field
    /// *"contains a value that is not an ASCII case-insensitive match for the value
    /// "websocket""* — **some member is not**, which is the negation of the other
    /// one and not a weaker form of it. The section stating what a server sends
    /// writes the same thing without a list, *"with value "websocket""*.
    ///
    /// So `Upgrade: websocket, h2c` in a response is a value the client must fail,
    /// and the inclusion reading — the reflex, and what this rule did — accepts it.
    /// Reading it as *the field value taken whole* would go one step too far the
    /// other way: `Upgrade` is `#protocol`, two field lines carrying `websocket`
    /// are one list with two members, and a message whose every member is the right
    /// one contains no value that is not a match.
    ///
    /// The general obligation to send an `Upgrade` in any 101 at all, and to name
    /// in it only protocols the client offered, is RFC 9110's and is
    /// `status_101_switching_protocols`'.
    // cite(RFC 6455 § 4.1): "If the response lacks an |Upgrade| header field or the |Upgrade| header field contains a value that is not an ASCII case-insensitive match for the value "websocket", the client MUST _Fail the WebSocket Connection_."
    // cite(RFC 6455 § 4.2.2): "An |Upgrade| header field with value "websocket" as per RFC 2616 [RFC2616]."
    fn upgrade_defect(resp_headers: &hyper::HeaderMap) -> Option<String> {
        let Some(raw) = combined_field_value_as_written(resp_headers, "upgrade") else {
            return Some("it carries no Upgrade header field".into());
        };
        if let Some(other) = list_members(&raw).find(|m| !m.eq_ignore_ascii_case("websocket")) {
            return Some(format!(
                "its Upgrade header field names `{}`, and the only protocol this response's \
                 Upgrade may name is `websocket`",
                shown_in_finding(other)
            ));
        }
        // A field that is present and names nothing is the first clause's case
        // reached by a second route: there is no `websocket` in it to match. The
        // neighbour reports the same message as a 101 whose `Upgrade` indicates no
        // protocol, from RFC 9110's side of it.
        if list_members(&raw).next().is_none() {
            return Some(format!(
                "its Upgrade header field is `{}`, which names no protocol at all where this \
                 response's Upgrade is defined with the value `websocket`",
                shown_in_finding(trim_ows(&raw))
            ));
        }
        None
    }

    /// The response's `Connection`, which *is* a list — the asymmetry with the
    /// field above is the document's own, stated one item later in the same list.
    ///
    /// The nomination question is `Connection`'s, and the shared predicate is what
    /// knows a `connection-option` is a field name and therefore compared without
    /// case; the sentence here asks for exactly that fold in its own words. The
    /// lines are joined before it looks, because `Connection` is one list however
    /// many of them carry it.
    // cite(RFC 6455 § 4.1): "If the response lacks a |Connection| header field or the |Connection| header field doesn't contain a token that is an ASCII case-insensitive match for the value "Upgrade", the client MUST _Fail the WebSocket Connection_."
    // cite(RFC 6455 § 4.2.2): "A |Connection| header field with value "Upgrade"."
    fn connection_defect(resp_headers: &hyper::HeaderMap) -> Option<String> {
        let Some(value) = combined_field_value_as_written(resp_headers, "connection") else {
            return Some(
                "it carries no Connection header field, so it names no connection-option at all"
                    .into(),
            );
        };
        if is_nominated_by_connection("upgrade", Some(&value)) {
            return None;
        }
        Some(format!(
            "its Connection header field is `{}`, which does not include the Upgrade token",
            shown_in_finding(&value)
        ))
    }

    /// `Sec-WebSocket-Accept`, the one field of this response that shows the server
    /// read the request rather than merely answering it.
    ///
    /// Nothing checks the value against its own `base64-value-non-empty` grammar,
    /// and nothing needs to: the comparison is against a derived value that is
    /// canonical base64 of twenty octets, so every value that grammar rejects this
    /// comparison rejects too — and with a message naming what the server should
    /// have written instead, which the grammar could not supply.
    ///
    /// The field is not list-based, so a second field line is not a second member:
    /// the combined value carries the comma the join writes and matches nothing.
    /// That is the finding, and it is worded from what the message says rather than
    /// from what one of its lines says.
    ///
    /// Returns `None` when the key is one [`Self::refusable_handshake`] objects to.
    /// There is no accept value to expect from a server handed a key that is not a
    /// nonce, and the finding about that exchange has already been made.
    // cite(RFC 6455 § 4.1): "If the response lacks a |Sec-WebSocket-Accept| header field or the |Sec-WebSocket-Accept| contains a value other than the base64-encoded SHA-1 of the concatenation of the |Sec-WebSocket-Key| (as a string, not base64-decoded) with the string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" but ignoring any leading and trailing whitespace, the client MUST _Fail the WebSocket Connection_."
    // cite(RFC 6455 § 4.2.2): "A |Sec-WebSocket-Accept| header field.  The value of this header field is constructed by concatenating /key/, defined above in step 4 in Section 4.2.2, with the string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", taking the SHA-1 hash of this concatenated value to obtain a 20-byte value and base64-encoding (see Section 4 of [RFC4648]) this 20-byte hash."
    fn accept_defect(
        req_headers: &hyper::HeaderMap,
        resp_headers: &hyper::HeaderMap,
    ) -> Option<String> {
        let key = combined_field_value_as_written(req_headers, "sec-websocket-key")?;
        let expected = compute_accept(&key)?;
        let Some(raw) = combined_field_value_as_written(resp_headers, "sec-websocket-accept")
        else {
            return Some("it carries no Sec-WebSocket-Accept header field".into());
        };
        // The clause of the sentence above that reads "but ignoring any leading and
        // trailing whitespace" — and `OWS` is what whitespace means on a value read
        // one `char` per octet. An %xA0 padding the value is `obs-text` a sender
        // wrote and not a space, so trimming it would compare a value nobody sent;
        // `trim_ows`'s own doc comment carries the two sentences that decide it.
        let value = trim_ows(&raw);
        if value == expected {
            return None;
        }
        Some(format!(
            "its Sec-WebSocket-Accept is `{}`, where the value derived from the request's \
             Sec-WebSocket-Key is `{expected}`",
            shown_in_finding(value)
        ))
    }

    /// `Sec-WebSocket-Extensions`, where the server's field answers the client's.
    ///
    /// One question, and both sections state it: an extension the client did not
    /// offer. The comparison is on the `extension-token` half of each member,
    /// because that is the name — the parameters after the `;` are the extension's
    /// own business, which § 9.1 says in as many words.
    ///
    /// Splitting the member on `;` without regard for quoting is safe here even
    /// though `extension-param` admits a `quoted-string`, because the same section
    /// requires the unescaped value to conform to `token` and `,` is no `tchar`; so
    /// no comma or semicolon a splitter could trip on survives inside a conforming
    /// value.
    ///
    /// The names are compared as written, the same choice and the same reason as
    /// the subprotocol below: this document says *"treated as an ASCII
    /// case-insensitive value"* at the two fields where it means it, and says
    /// nothing of the kind about an `extension-token`, which is a registered name
    /// rather than a string either side may respell.
    ///
    /// What this leaves unmeasured is the field's own grammar: `extension-list` is
    /// `1#extension`, with `extension-param` productions under it, and an empty
    /// list or a member deriving from no `extension` passes *here*.
    /// `sec_websocket_extensions_syntax` is the rule that reads it, in
    /// both directions and each field section on its own — including the RFC
    /// 2616 notation § 9.1 imports, under which a null list element conforms.
    // cite(RFC 6455 § 4.1): "If the response includes a |Sec-WebSocket-Extensions| header field and this header field indicates the use of an extension that was not present in the client's handshake (the server has indicated an extension not requested by the client), the client MUST _Fail the WebSocket Connection_."
    // cite(RFC 6455 § 4.2.2): "Extensions not listed by the client MUST NOT be listed."
    // cite(RFC 6455 § 9.1): "The extensions listed by the server in response represent the extensions actually in use for the connection."
    // cite(RFC 6455 § 9.1): "any extension parameters, and what constitutes a valid response by a server to a requested set of parameters by a client, will be defined by each such extension."
    // cite(RFC 6455 § 9.1): "Any extension-token used MUST be a registered token (see Section 11.4)."
    fn extensions_defect(
        req_headers: &hyper::HeaderMap,
        resp_headers: &hyper::HeaderMap,
    ) -> Option<String> {
        let raw = combined_field_value_as_written(resp_headers, "sec-websocket-extensions")?;
        let offered_raw = combined_field_value_as_written(req_headers, "sec-websocket-extensions")
            .unwrap_or_default();
        let offered: Vec<&str> = list_members(&offered_raw).map(extension_token).collect();
        for member in list_members(&raw) {
            let name = extension_token(member);
            if !offered.contains(&name) {
                return Some(format!(
                    "its Sec-WebSocket-Extensions names the extension `{}`, which the request it \
                     answers did not offer",
                    shown_in_finding(name)
                ));
            }
        }
        None
    }

    /// `Sec-WebSocket-Protocol`, which is one name in a response and a list of them
    /// in the request. The collected grammar gives the two directions different
    /// productions, and this is the field where that difference is a finding rather
    /// than a note.
    ///
    /// Three sentences, in the order a value fails them: the empty string is named
    /// as not a legal value, the production is one `token`, and the name has to be
    /// one the client offered.
    ///
    /// The last comparison is of what was written. This document folds case where
    /// it means to — the two fields above are each *"treated as an ASCII
    /// case-insensitive value"* in so many words — and says nothing of the kind
    /// here, nor in the sentence requiring the client's names to be unique strings,
    /// which the rule reading the request took the same way.
    ///
    /// A server that agrees to no subprotocol sends no field, and that absence is
    /// the null value rather than a defect, so the whole check is behind the
    /// field's presence.
    // cite(RFC 6455 § 4.1): "If the response includes a |Sec-WebSocket-Protocol| header field and this header field indicates the use of a subprotocol that was not present in the client's handshake (the server has indicated a subprotocol not requested by the client), the client MUST _Fail the WebSocket Connection_."
    // cite(RFC 6455 § 4.2.2): "The value chosen MUST be derived from the client's handshake, specifically by selecting one of the values from the |Sec-WebSocket-Protocol| field that the server is willing to use for this connection (if any)."
    // cite(RFC 6455 § 4.2.2): "if the server does not wish to agree to one of the suggested subprotocols, it MUST NOT send back a |Sec-WebSocket-Protocol| header field in its response"
    // cite(RFC 6455 § 4.2.2): "The empty string is not the same as the null value for these purposes and is not a legal value for this field."
    // cite(RFC 6455 § 4.3, label: Sec-WebSocket-Protocol-Server): "Sec-WebSocket-Protocol-Server = token"
    fn subprotocol_defect(
        req_headers: &hyper::HeaderMap,
        resp_headers: &hyper::HeaderMap,
    ) -> Option<String> {
        let raw = combined_field_value_as_written(resp_headers, "sec-websocket-protocol")?;
        let value = trim_ows(&raw);
        if value.is_empty() {
            return Some(
                "its Sec-WebSocket-Protocol is empty, and the empty string is named as not a \
                 legal value for this field — a server agreeing to no subprotocol sends no field \
                 at all"
                    .into(),
            );
        }
        // A comma is not a `tchar`, so the scan below would report it as one more
        // octet the production does not admit. It earns its own sentence: what the
        // server got wrong is not a character, it is that it answered with a list
        // where the grammar for its direction writes one name.
        if value.contains(',') {
            return Some(format!(
                "its Sec-WebSocket-Protocol is `{}`, and the server's field is one subprotocol \
                 name where the client's is a list of them",
                shown_in_finding(value)
            ));
        }
        if let Some(c) = crate::helpers::token::find_invalid_token_char(value) {
            return Some(format!(
                "its Sec-WebSocket-Protocol is `{}`, which holds {} and so derives from no \
                 `token`",
                shown_in_finding(value),
                describe_octet(c as u8)
            ));
        }
        let offered = combined_field_value_as_written(req_headers, "sec-websocket-protocol")
            .unwrap_or_default();
        // Membership is over the request's members as written, and that is total:
        // a member the client should not have sent is still a member it sent, so
        // no reading of the request leaves this comparison unable to answer.
        if list_members(&offered).any(|m| m == value) {
            return None;
        }
        Some(format!(
            "its Sec-WebSocket-Protocol names the subprotocol `{}`, which the request it answers \
             did not offer",
            shown_in_finding(value)
        ))
    }
}

/// The name half of one `Sec-WebSocket-Extensions` member.
///
/// `extension = extension-token *( ";" extension-param )`, so everything from the
/// first semicolon on is parameters and a member carrying none is all name. The
/// member arrives already `OWS`-trimmed by the list walk; what the split leaves is
/// trimmed again because the production prints no whitespace beside the semicolon
/// and a sender may have written some anyway.
// cite(RFC 6455 § 4.3, label: extension): "extension = extension-token *( ";" extension-param )"
fn extension_token(member: &str) -> &str {
    match member.split_once(';') {
        Some((name, _params)) => trim_ows(name),
        None => member,
    }
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_6455_4_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6455",
    section: Some("4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-4.1",
    note: "Client Requirements — the numbered list a client validates the server's response against, and the sentence handing every non-101 back to plain HTTP",
};
const RFC_6455_4_2_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6455",
    section: Some("4.2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-4.2.1",
    note: "Reading the Client's Opening Handshake — the description a handshake has to match, and the requirement to refuse one that does not, which is what makes a 101 over a malformed key the server's defect",
};
const RFC_6455_4_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6455",
    section: Some("4.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-4.2.2",
    note: "Sending the Server's Opening Handshake — what a server sends if it accepts, the five things it sends instead if it does not, and how `Sec-WebSocket-Accept`, `/subprotocol/` and `/extensions/` are derived from the request",
};
const RFC_6455_4_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6455",
    section: Some("4.3"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-4.3",
    note: "Collected ABNF — `Sec-WebSocket-Protocol-Server = token` against the client's `1#token`, and the `extension` production whose first half is the name",
};
const RFC_6455_9_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6455",
    section: Some("9.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-9.1",
    note: "Negotiating Extensions — the server's list is the extensions in use, each extension's own document defines what a valid answer to its parameters is, and an `extension-token` is a registered name",
};
const RFC_8441_5: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 8441",
    section: Some("5"),
    url: "https://www.rfc-editor.org/rfc/rfc8441.html#section-5",
    note: "Updates RFC 6455: over HTTP/2 the handshake is an extended CONNECT, `Connection` and `Upgrade` MUST NOT be included, and `Sec-WebSocket-Accept` is not processed — the sentences behind this rule's version gate",
};
const RFC_9220_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9220",
    section: Some("3"),
    url: "https://www.rfc-editor.org/rfc/rfc9220.html#section-3",
    note: "Carries RFC 8441's mechanism to HTTP/3 with identical semantics",
};

impl Rule for WebsocketHandshakeValid {
    fn id(&self) -> &'static str {
        "websocket_handshake_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
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
            let req = &tx.request;

            // Which captured exchanges are this document's opening handshake — the
            // method, the `Upgrade` keyword and the messaging syntax — is asked of the
            // shared gate, so that the rule measuring the request and this one measuring
            // the answer cannot disagree about which exchanges those are.
            opening_handshake_version(req)?;
            let resp = tx.response.as_ref()?;

            // The premise, and the sentence that used to sit on the method test above.
            //
            // A response other than 101 is not a handshake to measure: § 4.2.2's list of
            // what a server sends opens with the server *choosing to accept*, and the
            // same section names five other things a server does instead — client
            // authentication with a 401, a redirect with a 3xx, a 403 for an origin it
            // will not serve, a 404 for a resource it does not have, a 426 for a version
            // it does not speak. § 4.1 sends every one of them back to plain HTTP, where
            // the rest of this catalogue measures it.
            //
            // Demanding a 101 here reported all five as handshake defects, and the two
            // most common of them — an authentication challenge and a redirect — are
            // things the document explicitly says a server may do.
            // cite(RFC 6455 § 4.1): "If the status code received from the server is not 101, the client handles the response per HTTP [RFC2616] procedures."
            // cite(RFC 6455 § 4.1): "In particular, the client might perform authentication if it receives a 401 status code; the server might redirect the client using a 3xx status code (but clients are not required to follow them), etc.  Otherwise, proceed as follows."
            // cite(RFC 6455 § 4.2.2): "If the server chooses to accept the incoming connection, it MUST reply with a valid HTTP response indicating the following."
            // cite(RFC 6455 § 4.2.2): "The server can perform additional client authentication, for example, by returning a 401 status code with the corresponding |WWW-Authenticate| header field as described in [RFC2616]."
            // cite(RFC 6455 § 4.2.2): "The server MAY redirect the client using a 3xx status code [RFC2616]."
            // cite(RFC 6455 § 4.2.2): "If the server does not wish to accept this connection, it MUST return an appropriate HTTP error code (e.g., 403 Forbidden) and abort the WebSocket handshake described in this section."
            // cite(RFC 6455 § 4.2.2): "If the requested service is not available, the server MUST send an appropriate HTTP error code (such as 404 Not Found) and abort the WebSocket handshake."
            // cite(RFC 6455 § 4.2.2): "A Status-Line with a 101 response code as per RFC 2616 [RFC2616]."
            if resp.status != 101 {
                return None;
            }

            // Every gate above ends the rule, and reading the configuration is several
            // map probes and a hash of the id — so only an exchange about to be measured
            // pays for it.

            // § 4.1's numbered order, which is the order a client validating this
            // response would reach them, with the question about the handshake's
            // admissibility ahead of the questions about its fields. One message carries
            // one finding, so the first defect is the one reported.
            let defect = [
                Self::refusable_handshake(&req.headers),
                Self::upgrade_defect(&resp.headers),
                Self::connection_defect(&resp.headers),
                Self::accept_defect(&req.headers, &resp.headers),
                Self::extensions_defect(&req.headers, &resp.headers),
                Self::subprotocol_defect(&req.headers, &resp.headers),
            ]
            .into_iter()
            .flatten()
            .next()?;

            Some(self.violation(
                ctx.severity,
                format!("This 101 completes a WebSocket opening handshake, but {defect}"),
            ))
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("WebSocket handshake validity")
    }

    fn description(&self) -> &'static str {
        "Measures the server's half of a WebSocket opening handshake against the request it answers, following the list RFC 6455 § 4.1 gives a client for validating that response:\n\n- `Upgrade` is `websocket`. In a response that is one value, not a list: § 4.1 has the client fail the connection when the field *contains a value that is not an ASCII case-insensitive match* for `websocket`, and § 4.2.2 asks for the field *with value \"websocket\"*. The request's `Upgrade`, by contrast, need only *include the \"websocket\" keyword*, and `sec_websocket_headers_consistent` reads it that way.\n- `Connection` names the `Upgrade` connection-option — a list, one item later in the same numbered list.\n- `Sec-WebSocket-Accept` is the base64 SHA-1 of the request's `Sec-WebSocket-Key` concatenated with the well-known GUID. The finding names the value the server should have written.\n- `Sec-WebSocket-Extensions`, when present, names only extensions the request offered.\n- `Sec-WebSocket-Protocol`, when present, is a single `token` — the server's production, where the client's is a list — that is not the empty string and that the request offered. A server agreeing to no subprotocol sends no field.\n\nOne finding is about the request rather than the response, and it is one only a rule holding both halves can make: a `101` answering a handshake whose `Sec-WebSocket-Key` is absent or is not a sixteen-octet nonce. RFC 6455 § 4.2.1 requires a server to stop processing such a handshake and answer with an error status, so completing it is the server's defect; the value itself is reported separately, against the client, by `sec_websocket_headers_consistent`.\n\n**Only `101` responses are measured.** RFC 6455 § 4.2.2 lists what a server sends *if the server chooses to accept the incoming connection*, and names five things it does instead — a `401` challenge, a `3xx` redirect, a `403` for an origin it will not serve, a `404` for a resource it does not have, a `426` for a version it does not speak. § 4.1 hands all of them to ordinary HTTP processing, where the rest of this catalogue measures them, so a non-`101` answer is a refusal rather than a malformed handshake.\n\nOnly HTTP/1.x exchanges are measured: over HTTP/2 and HTTP/3 the handshake is an extended CONNECT carrying `:protocol` (RFC 8441, RFC 9220), where `Connection` and `Upgrade` are forbidden and `Sec-WebSocket-Accept` is not sent at all.\n\nTwo neighbours own the sentences this rule does not. The obligation to send an `Upgrade` in *any* `101`, and to name in it only protocols the client offered, is RFC 9110's and belongs to `status_101_switching_protocols`. `Sec-WebSocket-Version: 13` is asked of the request by `sec_websocket_headers_consistent` and is deliberately not asked of the server here: RFC 6455 § 4.2.1's list makes every one of its items a MUST-refuse, while § 4.2.2 aborts a handshake only for a version *that does not match a version understood by the server* — a fact about the server, which a `101` is that server asserting. `Sec-WebSocket-Extensions` is measured here only against what the request offered; its own grammar (`extension-list`, `extension-param`) is `sec_websocket_extensions_syntax`'s, in both directions."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_6455_4_1,
            RFC_6455_4_2_1,
            RFC_6455_4_2_2,
            RFC_6455_4_3,
            RFC_6455_9_1,
            RFC_8441_5,
            RFC_9220_3,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /chat HTTP/1.1\nHost: server.example.com\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\nSec-WebSocket-Version: 13\n\nHTTP/1.1 101 Switching Protocols\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a refusal is not a malformed handshake)"),
                snippet: "GET /chat HTTP/1.1\nHost: server.example.com\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\nSec-WebSocket-Version: 13\n\nHTTP/1.1 401 Unauthorized\nWWW-Authenticate: Basic realm=\"chat\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(mismatched accept)"),
                snippet: "GET /chat HTTP/1.1\nHost: server.example.com\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\nSec-WebSocket-Version: 13\n\nHTTP/1.1 101 Switching Protocols\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Accept: WRONG==",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a subprotocol the client never offered)"),
                snippet: "GET /chat HTTP/1.1\nHost: server.example.com\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\nSec-WebSocket-Version: 13\nSec-WebSocket-Protocol: chat\n\nHTTP/1.1 101 Switching Protocols\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\nSec-WebSocket-Protocol: superchat",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &WebsocketHandshakeValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// The key and accept value RFC 6455 carries through its worked handshake, in
    /// § 1.2, § 4.2.2's NOTE and Appendix A.1.
    const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
    const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    fn make_ws_tx(
        req_headers: Vec<(&str, &str)>,
        resp_status: u16,
        resp_headers: Vec<(&str, &str)>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(resp_status, &[]);
        tx.request.method = "GET".into();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&req_headers);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&resp_headers);
        tx
    }

    /// A well-formed handshake request, for the tests whose subject is the answer.
    fn handshake_request() -> Vec<(&'static str, &'static str)> {
        vec![
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
            ("sec-websocket-key", KEY),
            ("sec-websocket-version", "13"),
        ]
    }

    /// The answer RFC 6455 § 1.2 prints to that request.
    fn handshake_response() -> Vec<(&'static str, &'static str)> {
        vec![
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
            ("sec-websocket-accept", ACCEPT),
        ]
    }

    fn run(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        crate::test_helpers::run_rule(
            &WebsocketHandshakeValid,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "websocket_handshake_valid",
            ]),
        )
    }

    /// The exchange the document itself prints.
    #[rstest]
    fn the_specifications_own_handshake_is_clean() {
        let tx = make_ws_tx(handshake_request(), 101, handshake_response());
        assert!(run(&tx).is_none());
    }

    /// The premise. Every one of these is something RFC 6455 § 4.2.2 names a server
    /// doing instead of accepting, and each was reported as a handshake defect.
    #[rstest]
    #[case(401)] // § 4.2.2 step 2, client authentication
    #[case(302)] // § 4.2.2 step 3, a redirect
    #[case(403)] // § 4.2.2 /origin/, an origin the server will not serve
    #[case(404)] // § 4.2.2 /resource name/, a service it does not provide
    #[case(426)] // § 4.2.2 /version/, a version it does not speak
    #[case(200)] // anything else is still ordinary HTTP, per § 4.1 item 1
    fn a_refusal_is_not_a_malformed_handshake(#[case] status: u16) {
        let tx = make_ws_tx(handshake_request(), status, vec![]);
        assert!(run(&tx).is_none());
    }

    /// The server completed a handshake § 4.2.1 required it to refuse. The value is
    /// the client's mistake and is reported against the client elsewhere; that the
    /// exchange reached a 101 is the server's.
    #[rstest]
    #[case(vec![("upgrade", "websocket"), ("connection", "Upgrade")], "carries no Sec-WebSocket-Key")]
    #[case(vec![("upgrade", "websocket"), ("connection", "Upgrade"), ("sec-websocket-key", "!!notbase64!!")], "not the nonce")]
    #[case(vec![("upgrade", "websocket"), ("connection", "Upgrade"), ("sec-websocket-key", "YQ==")], "not the nonce")]
    fn a_hundred_and_one_over_a_handshake_that_had_to_be_refused(
        #[case] req_headers: Vec<(&str, &str)>,
        #[case] expected: &str,
    ) {
        let tx = make_ws_tx(req_headers, 101, handshake_response());
        let v = run(&tx).unwrap();
        assert!(v.message.contains(expected), "{}", v.message);
        assert!(v.message.contains("required to refuse"), "{}", v.message);
    }

    /// § 4.2.1 makes every item of its description a MUST-refuse and § 4.2.2 aborts
    /// only over a version the server does not understand — so a 101 is that server
    /// saying it did, and this rule does not argue with it. The request's own field
    /// is `sec_websocket_headers_consistent`'s.
    #[rstest]
    fn a_version_other_than_thirteen_is_not_this_rules_finding() {
        let mut req = handshake_request();
        req.retain(|(name, _)| *name != "sec-websocket-version");
        req.push(("sec-websocket-version", "25"));
        let tx = make_ws_tx(req, 101, handshake_response());
        assert!(run(&tx).is_none());
    }

    /// The question is *some member is not `websocket`*, which is the negation of
    /// the request's *some member is*, not a stricter form of it. A member beside
    /// `websocket` is a value the client must fail; a second field line carrying
    /// the same name is one list with two members, all of them the right one.
    #[rstest]
    #[case("websocket", None)]
    #[case("WebSocket", None)]
    #[case("  websocket\t", None)]
    #[case("websocket, websocket", None)]
    #[case("notwebsocket", Some("names `notwebsocket`"))]
    #[case("websocket, h2c", Some("names `h2c`"))]
    #[case("", Some("names no protocol at all"))]
    #[case("  ,  ", Some("names no protocol at all"))]
    fn the_response_upgrade_names_websocket_and_nothing_else(
        #[case] value: &str,
        #[case] expected: Option<&str>,
    ) {
        let tx = make_ws_tx(
            handshake_request(),
            101,
            vec![
                ("upgrade", value),
                ("connection", "Upgrade"),
                ("sec-websocket-accept", ACCEPT),
            ],
        );
        match expected {
            None => assert!(run(&tx).is_none(), "{value}"),
            Some(text) => assert!(run(&tx).unwrap().message.contains(text), "{value}"),
        }
    }

    /// Two field lines are one list, and the finding must not be a message that
    /// contradicts itself by quoting the comma the join wrote.
    #[rstest]
    fn two_upgrade_field_lines_carrying_the_same_name() {
        let tx = make_ws_tx(
            handshake_request(),
            101,
            vec![
                ("upgrade", "websocket"),
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-accept", ACCEPT),
            ],
        );
        assert!(run(&tx).is_none());
    }

    #[rstest]
    fn the_response_upgrade_is_required() {
        let tx = make_ws_tx(
            handshake_request(),
            101,
            vec![("connection", "Upgrade"), ("sec-websocket-accept", ACCEPT)],
        );
        assert!(run(&tx)
            .unwrap()
            .message
            .contains("carries no Upgrade header field"));
    }

    /// `Connection` is a list, and it is one list however many field lines carry
    /// it — the reading `get_header_str` had, which stops at the first line, called
    /// the second of these a response naming no `Upgrade`.
    #[rstest]
    #[case(vec!["Upgrade"], None)]
    #[case(vec!["keep-alive", "Upgrade"], None)]
    #[case(vec!["keep-alive"], Some("does not include the Upgrade token"))]
    fn the_response_connection_is_one_list(
        #[case] lines: Vec<&str>,
        #[case] expected: Option<&str>,
    ) {
        let mut resp: Vec<(&str, &str)> =
            vec![("upgrade", "websocket"), ("sec-websocket-accept", ACCEPT)];
        for line in &lines {
            resp.push(("connection", line));
        }
        let tx = make_ws_tx(handshake_request(), 101, resp);
        match expected {
            None => assert!(run(&tx).is_none()),
            Some(text) => assert!(run(&tx).unwrap().message.contains(text)),
        }
    }

    #[rstest]
    fn the_response_connection_is_required() {
        let tx = make_ws_tx(
            handshake_request(),
            101,
            vec![("upgrade", "websocket"), ("sec-websocket-accept", ACCEPT)],
        );
        assert!(run(&tx)
            .unwrap()
            .message
            .contains("carries no Connection header field"));
    }

    /// A `Connection` value holding an `obs-text` octet is a value, and the finding
    /// is about that value. Read through `to_str` the whole field vanished and the
    /// rule reported the field as missing — a claim about the message where the
    /// truth is about what is in it.
    #[rstest]
    fn an_obs_text_connection_value_is_not_a_missing_field() {
        let mut tx = make_ws_tx(handshake_request(), 101, vec![]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_octet_pairs(&[
                ("upgrade", b"websocket"),
                ("connection", b"Upgrade\xe9"),
                ("sec-websocket-accept", ACCEPT.as_bytes()),
            ]);
        let v = run(&tx).unwrap();
        assert!(
            v.message.contains("does not include the Upgrade token"),
            "{}",
            v.message
        );
        assert!(
            !v.message.contains("carries no Connection"),
            "{}",
            v.message
        );
    }

    #[rstest]
    fn the_accept_value_is_missing_or_wrong() {
        let tx = make_ws_tx(
            handshake_request(),
            101,
            vec![("upgrade", "websocket"), ("connection", "Upgrade")],
        );
        assert!(run(&tx)
            .unwrap()
            .message
            .contains("carries no Sec-WebSocket-Accept header field"));

        let tx = make_ws_tx(
            handshake_request(),
            101,
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-accept", "wrongvalue"),
            ],
        );
        let v = run(&tx).unwrap();
        assert!(v.message.contains(ACCEPT), "{}", v.message);
    }

    /// The whitespace this comparison ignores is `OWS`. An octet that merely looks
    /// like a space is `obs-text` a sender wrote, and the value it pads is not the
    /// derived one.
    #[rstest]
    fn only_ows_is_ignored_beside_the_accept_value() {
        let padded = format!("  {ACCEPT}\t");
        let tx = make_ws_tx(
            handshake_request(),
            101,
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-accept", &padded),
            ],
        );
        assert!(run(&tx).is_none());

        // One octet, %xA0, and not the two that `"\u{a0}"` becomes when a Rust
        // string is read as bytes. The finding is that the value does not match;
        // if `trim_ows` were `str::trim` there would be no violation to unwrap.
        let mut tx = make_ws_tx(handshake_request(), 101, vec![]);
        let padded = [b"\xa0".as_slice(), ACCEPT.as_bytes()].concat();
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_octet_pairs(&[
                ("upgrade", b"websocket"),
                ("connection", b"Upgrade"),
                ("sec-websocket-accept", &padded),
            ]);
        let v = run(&tx).unwrap();
        assert!(
            v.message.contains("its Sec-WebSocket-Accept is"),
            "{}",
            v.message
        );
    }

    /// § 4.1's NOTE prints `AQIDBAUGBwgJCgsMDQ4PEC==` as the field value for the
    /// octets 0x01 through 0x10, and its last symbol carries bits a conforming
    /// encoder zeroes. § 4.2.1 item 5 asks for a value that decodes to sixteen
    /// bytes, which this does, so the server was owed no refusal — and the accept
    /// value it should have echoed is derived from the string as written, which is
    /// what the server is told it need not decode.
    ///
    /// The value is still a finding against the *client*, in the rule that reads
    /// the request. This rule reporting it against the server would blame one party
    /// for another's spelling on the strength of a sentence addressed to neither.
    #[rstest]
    fn the_notes_own_key_is_not_a_handshake_the_server_owed_a_refusal() {
        let key = "AQIDBAUGBwgJCgsMDQ4PEC==";
        let accept = crate::helpers::websocket::compute_accept(key).expect("derivable");
        let tx = make_ws_tx(
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-key", key),
                ("sec-websocket-version", "13"),
            ],
            101,
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-accept", &accept),
            ],
        );
        assert!(run(&tx).is_none());

        // And the server is still measured on it: the derivation happens, so a
        // wrong echo is still reported rather than skipped.
        let tx = make_ws_tx(
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-key", key),
                ("sec-websocket-version", "13"),
            ],
            101,
            vec![
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-accept", ACCEPT),
            ],
        );
        assert!(run(&tx).unwrap().message.contains(&accept));
    }

    /// The server's subprotocol field is one `token` the client offered.
    #[rstest]
    #[case("chat", None)]
    #[case("superchat", None)]
    #[case("mqtt", Some("did not offer"))]
    #[case("Chat", Some("did not offer"))]
    #[case("", Some("not a legal value"))]
    #[case("   ", Some("not a legal value"))]
    #[case("chat, superchat", Some("one subprotocol name"))]
    #[case("cha t", Some("derives from no `token`"))]
    fn the_servers_subprotocol(#[case] value: &str, #[case] expected: Option<&str>) {
        let mut req = handshake_request();
        req.push(("sec-websocket-protocol", "chat, superchat"));
        let mut resp = handshake_response();
        resp.push(("sec-websocket-protocol", value));
        let tx = make_ws_tx(req, 101, resp);
        match expected {
            None => assert!(run(&tx).is_none()),
            Some(text) => assert!(run(&tx).unwrap().message.contains(text), "{value}"),
        }
    }

    /// No field is the null value, which is what a server agreeing to nothing
    /// sends; a field answering a request that offered none is a name the client
    /// never asked for.
    #[rstest]
    fn a_subprotocol_answering_a_request_that_offered_none() {
        let tx = make_ws_tx(handshake_request(), 101, handshake_response());
        assert!(run(&tx).is_none());

        let mut resp = handshake_response();
        resp.push(("sec-websocket-protocol", "chat"));
        let tx = make_ws_tx(handshake_request(), 101, resp);
        assert!(run(&tx).unwrap().message.contains("did not offer"));
    }

    /// Extensions are compared on the name half of each member; the parameters
    /// after the `;` belong to the extension's own document.
    #[rstest]
    #[case("permessage-deflate", None)]
    #[case("permessage-deflate; client_max_window_bits=15", None)]
    #[case("mux", Some("did not offer"))]
    #[case("permessage-deflate, mux", Some("did not offer"))]
    fn the_servers_extensions(#[case] value: &str, #[case] expected: Option<&str>) {
        let mut req = handshake_request();
        req.push((
            "sec-websocket-extensions",
            "permessage-deflate; client_max_window_bits",
        ));
        let mut resp = handshake_response();
        resp.push(("sec-websocket-extensions", value));
        let tx = make_ws_tx(req, 101, resp);
        match expected {
            None => assert!(run(&tx).is_none()),
            Some(text) => assert!(run(&tx).unwrap().message.contains(text), "{value}"),
        }
    }

    /// § 9.1 says the field may be split across lines and means the same thing, so
    /// an extension offered on a second request line was offered.
    #[rstest]
    fn a_request_extension_list_split_across_lines() {
        let mut req = handshake_request();
        req.push(("sec-websocket-extensions", "permessage-deflate"));
        req.push(("sec-websocket-extensions", "mux; max-channels=4"));
        let mut resp = handshake_response();
        resp.push(("sec-websocket-extensions", "mux"));
        let tx = make_ws_tx(req, 101, resp);
        assert!(run(&tx).is_none());
    }

    /// The gate is the shared one, so what is not a handshake to the rule reading
    /// the request is not one here either.
    ///
    /// Every exchange below carries a response this rule *would* report if it
    /// measured it — an empty 101 fails four of the six checks — so each assertion
    /// fails if its half of the gate stops working. Asserting silence over an
    /// otherwise clean exchange would pass with no gate at all.
    #[rstest]
    fn exchanges_that_are_not_this_documents_handshake() {
        // Not a GET.
        let mut tx = make_ws_tx(handshake_request(), 101, vec![]);
        tx.request.method = "POST".into();
        assert!(run(&tx).is_none());

        // A GET whose `Upgrade` names some other protocol.
        let mut tx = make_ws_tx(handshake_request(), 101, vec![]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("upgrade", "h2c")]);
        assert!(run(&tx).is_none());

        // Over HTTP/2 and HTTP/3 the handshake is an extended CONNECT: none of the
        // fields measured here may be sent, and `Sec-WebSocket-Accept` is not
        // processed at all. The version is an `HTTP-version` token — spelling it
        // "2.0" would fail the parse instead, and pass this test for the wrong
        // reason.
        for version in ["HTTP/2.0", "HTTP/3.0"] {
            let mut tx = make_ws_tx(handshake_request(), 101, vec![]);
            tx.request.version = version.into();
            assert!(run(&tx).is_none(), "{version}");
        }

        // A value deriving from no `HTTP-version` names no messaging syntax, so
        // there is no handshake to claim either way.
        let mut tx = make_ws_tx(handshake_request(), 101, vec![]);
        tx.request.version = "HTTP/3".into();
        assert!(run(&tx).is_none());

        let mut tx = make_ws_tx(handshake_request(), 101, handshake_response());
        tx.response = None;
        assert!(run(&tx).is_none());
    }

    /// The exchange each half of the gate above is standing between the rule and:
    /// with the gate removed, every one of those cases reports this.
    #[rstest]
    fn the_response_those_gates_are_keeping_out() {
        let tx = make_ws_tx(handshake_request(), 101, vec![]);
        assert!(run(&tx).is_some());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "websocket_handshake_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
