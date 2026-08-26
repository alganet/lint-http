<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Trailer Fields Validity

## Description

Validates the fields that actually arrive in a message's trailer section — the fields sent after the content, in a request or a response.

A field is reported for one of three reasons:

- **Its own definition does not permit the usage.** RFC 9110 §6.5.1: a sender MUST NOT generate a trailer field unless it knows the corresponding field definition permits it. Reported for the fields whose definitions this linter holds and which do not: message framing (`Content-Length`, `Transfer-Encoding`), routing (`Host`, `Forwarded`), request modifiers (`Cache-Control`, `Expect`, `Max-Forwards`, `Pragma`, `Range`, `TE`, and the five `If-*` conditionals), authentication (`Authorization`, `WWW-Authenticate`, `Proxy-Authenticate`, `Proxy-Authorization`), response controls (`Age`, `Date`, `Expires`, `Location`, `Retry-After`, `Vary`, `Warning`), content format (`Content-Encoding`, `Content-Range`, `Content-Type`), the connection-specific `Connection`, `Keep-Alive`, `Proxy-Connection` and `Upgrade`, `Trailer` itself, which would announce a section the recipient has finished reading, and `Early-Data`, whose definition (RFC 8470 §5.1) is the one that answers §6.5.1's question by name: "An Early-Data header field MUST NOT be included in responses or request trailers."
- **This message's own `Connection` names it.** A field listed as a connection-option carries control information for the current connection, and RFC 9110 §7.6.1 has every intermediary remove such a field from the trailer section before forwarding. The `Connection` consulted is the one in the same message as the trailer section, across all of its field lines.
- **The `Trailer` declaration did not indicate it.** Where a message carries a `Trailer` header field, RFC 9110 §6.6.2's SHOULD asks it to indicate which fields might appear in the trailers, so a field that arrives unannounced is reported. `Trailer:` carrying nothing is a legal, empty declaration that announces no field at all — it is read, not treated as missing.

**Scope limit, and it is the requirement's shape rather than an omission.** §6.5.1 is deny-by-default — RFC 9110 §16.3.2 says a new field is not allowable in trailers unless its definition says so — while the first check above is a list of names, which answers the opposite question. It cannot be inverted here: for a field this linter holds no definition of (`X-Checksum`, `Grpc-Status`), only the sender knows whether its definition permits the usage, and reporting all of them would report the senders that read their own specification. So a field absent from the list passes, and its passing is not a verdict. For the same reason, `Authentication-Info` and `Proxy-Authentication-Info` are *not* reported: RFC 9110 §11.6.3 and §11.7.3 permit both in a trailer section when the authentication scheme allows it, and the scheme is not visible here.

Two further sentences of §6.5.1 are left alone deliberately: that a trailer section is only possible where the framing enables one (a trailer section reaches this rule only because framing delivered it), and that a server SHOULD NOT send trailer fields it *believes* the user agent needs to receive (a belief, which no capture records).

This rule complements `trailer_header_valid`, which reads the `Trailer` declaration's own syntax. Announcing a field and sending one are two acts; this rule judges the second.

## Specifications

- [RFC 9110 §6.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5): Trailer fields: what a trailer section is, and why what it carries cannot unmake a routing or processing choice already made from the header section
- [RFC 9110 §6.5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5.1): The MUST NOT behind the first finding, and it is deny-by-default: a trailer field is permitted only where the field's own definition says so. This rule reports the subset it can name; a field it does not recognise is not thereby approved
- [RFC 9110 §6.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.6.2): The `Trailer` field, whose SHOULD asks a sender to indicate which fields might appear — the sentence behind the undeclared-field finding, which said §6.5 in the finding text
- [RFC 9110 §7.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1): `Connection`: naming a field as a connection-option makes its value control information for this connection, and every intermediary removes it from the trailer section before forwarding
- [RFC 9110 §11.6.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.3): `Authentication-Info` may be sent as a trailer field when the authentication scheme allows it — a field §6.5.1's authentication category would forbid, permitted by name in its own definition. §11.7.3 says the same of `Proxy-Authentication-Info`. Neither is reported
- [RFC 9110 §16.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-16.3.2): The registry's advice to authors of new fields, and the sentence that makes §6.5.1 deny-by-default: a field is not allowable in trailers unless its definition says it is
- [RFC 9112 §7.1.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1.2): The chunked transfer coding's trailer section — HTTP/1.1's framing mechanism for the section this rule reads, and the reason the framing precondition in §6.5.1 needs no check here

## Configuration

```toml
[rules.trailer_fields_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good Announced before the content, sent after it

```http
HTTP/1.1 200 OK
Trailer: X-Checksum
Transfer-Encoding: chunked

<chunked body>
X-Checksum: abc123
```

### ✅ Good A field §6.5.1's categories would forbid and its own definition permits

```http
HTTP/1.1 200 OK
Trailer: Authentication-Info
Transfer-Encoding: chunked

<chunked body>
Authentication-Info: nextnonce="a1b2c3"
```

### ❌ Bad Message framing, which the recipient needed before the content

```http
HTTP/1.1 200 OK
Transfer-Encoding: chunked

<chunked body>
Content-Length: 42
```

### ❌ Bad Control information for this connection, by the sender's own account

```http
HTTP/1.1 200 OK
Connection: keep-alive, X-Hop-State
Transfer-Encoding: chunked

<chunked body>
X-Hop-State: value
```

### ❌ Bad Sent after the content, and the declaration did not indicate it

```http
HTTP/1.1 200 OK
Trailer: X-Checksum
Transfer-Encoding: chunked

<chunked body>
X-Signature: sig-value
```
