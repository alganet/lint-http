<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Te Header Valid

## Description

Validates the `TE` request header field — the transfer codings a client is able to accept in a response, and whether it will keep a trailer section.

The field is `TE = [ t-codings *( OWS "," OWS t-codings ) ]` (RFC 9110 §A) and a member is `t-codings = "trailers" / ( transfer-coding [ weight ] )` (§10.1.4). `trailers` is a keyword occupying the whole of its alternative, so it takes neither a parameter nor a weight — the alternative that admits either is the other one. A coding may carry `transfer-parameter = token BWS "=" BWS ( token / quoted-string )` parameters and a `weight`, whose `q` is a `qvalue`: 0 or 1 with at most three digits after the point (§12.4.2), matched case-insensitively because RFC 9112 §7.3 says the pseudo-parameter's name is. Whitespace around a *parameter's* `=` is `BWS`, which the production admits for historical reasons only and which a sender MUST NOT generate (§5.6.3); around the *weight's* `=` it is not admitted at all, since `weight = OWS ";" OWS "q=" qvalue` prints `q=` as one literal — the same three characters of whitespace, two productions, and only one of them has a sentence about bad whitespace to quote. No member may be empty (§5.6.1.1) — `TE: deflate,,gzip` is a list a sender must not generate — while an **empty field value** is a different thing and is not reported: `TE:` is a list of no members, and RFC 9112 §7.4 prints it as one of its three examples and says what it means (only `chunked` is acceptable).

**The coding name itself is not measured here.** `transfer-coding` is a `token`, and `transfer_coding_registered` is the rule that reads the names `TE` and `Transfer-Encoding` carry: it reports a name that is not a token, a member naming no coding at all, an unrecognized name, and `chunked` in `TE` — which RFC 9112 §7.4 forbids outright, since a client cannot decline a coding that is always acceptable. This rule owns what follows the name.

A sender of `TE` MUST also send a `TE` connection option within `Connection` (§10.1.4), which is what stops an intermediary from forwarding a field that applies to one hop. **That requirement is asked only of the versions of HTTP that have a `Connection` field.** HTTP/2 and HTTP/3 convey connection-specific metadata by other means, and an endpoint MUST NOT generate a message carrying the field at all (RFC 9113 §8.2.2, RFC 9114 §4.2) — so a request over those versions is not reported for omitting an option it is not allowed to send. What a `TE` value may hold there — `trailers` and nothing else — is those documents' requirement rather than this rule's; `no_connection_specific_fields` reports it for both of them.

Scope: this rule reads a request's header section, and a response's only to report that the field is there. Where the field appears on several lines in one section they are one value (§5.2), so an empty member written at a line boundary is an empty member. A value carrying an octet outside US-ASCII is measured rather than skipped: `obs-text` is an octet `field-content` admits and neither `token` nor `qvalue` does, so it is reported at the parameter that carried it instead of turning the whole field — and the connection-option requirement with it — into silence. Whether `TE` may appear in a **trailer** section is §6.5.1's question and `trailer_fields_valid`'s, which holds the table `TE` is listed in.

**A response carrying `TE` is reported, and RFC 9110 states no prohibition.** §10.1 gathers the request context fields and §10.1.4 defines this one as describing the client's capabilities; no sentence gives a `TE` in a response a meaning, and none forbids one in so many words either. The finding says that and no more. **It is asked only of a response carried by HTTP/1.x.** Over HTTP/2 and HTTP/3 there is a MUST NOT — a response is not the request their exception is written for, so the field is connection-specific there and the message is malformed — and `no_connection_specific_fields` reports it on each with that version's own sentence, which is the stronger of the two readings. Reporting it here as well would be two findings for one field.

## Specifications

- [RFC 9110 §5.6.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.3): Whitespace — `BWS` is printed where a grammar allows optional whitespace for historical reasons only, with a MUST NOT on the sender and a matching MUST on the recipient to remove it before interpreting the element
- [RFC 9110 §10.1.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.4): TE — what a member states, the grammar of its parameters, and the `TE` connection option a sender of the field MUST also send
- [RFC 9110 §10.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1): Request Context Fields — the five fields whose subjects are the user, user agent and resource behind a request; the section split the direction is read from
- [RFC 9110 §A](https://www.rfc-editor.org/rfc/rfc9110.html#appendix-A): The collected grammar, where the list construct is expanded for a sender and `t-codings` is written out — the alternation that gives the `trailers` keyword neither a parameter nor a weight
- [RFC 9110 §12.4.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.2): Quality Values — `weight = OWS ";" OWS "q=" qvalue`, the `qvalue` production and its three-digit fraction, the case-insensitive `q` parameter name, and what a weight of zero means
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The list construct — `1#element => element *( OWS "," OWS element )`, and the sender's MUST NOT against an empty element
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits
- [RFC 9110 §5.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4): `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` — the two delimiters, the class between them, and the backslash escape
- [RFC 9110 §5.6.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6): Parameters — `parameters = *( OWS ";" OWS [ parameter ] )`, the `name=value` pair inside it with neither half optional, and the bracketing that leaves a trailing `;` conforming
- [RFC 9110 §7.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1): The `Connection` field the option is listed in, and the note that some versions of HTTP do not allow the field at all
- [RFC 9112 §7.4](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.4): HTTP/1.1's own account of the field: what an empty value means, the `q` rank, the `chunked` MUST NOT, and why the connection option is required
- [RFC 9112 §7.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.3): `q` is a pseudo-parameter rather than a transfer-parameter, and its name is case-insensitive
- [RFC 9113 §8.2.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2): HTTP/2 forbids the `Connection` field, and excepts `TE` in a request when it holds nothing but `trailers`
- [RFC 9114 §4.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2): The same for HTTP/3. `no_connection_specific_fields` is the rule that enforces the value restriction, on both versions
- [RFC 9110 §6.5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5.1): What the `trailers` keyword says on the wire: the client will not discard a trailer section

## Configuration

```toml
[rules.te_header_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /resource HTTP/1.1
Host: example.com
Connection: TE
TE: trailers
```

### ✅ Good (codings ranked by quality)

```http
GET /resource HTTP/1.1
Host: example.com
Connection: keep-alive, TE
TE: trailers, deflate;q=0.5
```

### ❌ Bad (TE without Connection: TE)

```http
GET /resource HTTP/1.1
Host: example.com
TE: deflate;q=0.8
```

### ❌ Bad (a weight on the trailers keyword)

```http
GET /resource HTTP/1.1
Host: example.com
Connection: TE
TE: trailers;q=0.5
```

### ❌ Bad (an empty list element)

```http
GET /resource HTTP/1.1
Host: example.com
Connection: TE
TE: deflate,,gzip
```

### ❌ Bad (TE in response)

```http
HTTP/1.1 200 OK
TE: trailers
```
