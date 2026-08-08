<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Trailer Headers Valid

## Description

Validates the `Trailer` header field's own value — the list of field names a sender says it anticipates sending as trailer fields.

The field is `Trailer = [ field-name *( OWS "," OWS field-name ) ]` (RFC 9110 §A). Every member must therefore be a `token`, and no member may be empty: `Trailer: ETag,,Expires` is a list a sender MUST NOT generate (RFC 9110 §5.6.1.1). An **empty value** is a different thing and is not reported — the production's outer brackets make a list of no field names a list, so `Trailer:` says only that nothing is announced. Where the field appears on several lines, the lines are one list (RFC 9110 §5.2), so an empty member written at a line boundary is an empty member.

A member is reported when it names a field that cannot reach a recipient's trailer section:

- **Nominated by this message's own `Connection`.** An intermediary MUST remove any header *or trailer* field named as a connection-option before forwarding (RFC 9110 §7.6.1), so the announced trailer cannot arrive. The `Connection` consulted is the one in the same field section as the `Trailer`; a request's connection options say nothing about a response's trailers.
- **Connection-specific whatever the message says** — `Connection`, `Keep-Alive`, `Proxy-Connection`, `TE`, `Transfer-Encoding`, `Upgrade`, `Proxy-Authenticate`, `Proxy-Authorization`, and each for a different sentence. RFC 9110 §7.6.1 lists five of them (`Proxy-Connection`, `Keep-Alive`, `TE`, `Transfer-Encoding`, `Upgrade`) as fields an intermediary SHOULD remove whether or not a connection-option names them; `Connection` itself is removed by that section's MUST, once the intermediary has acted on it; and `Proxy-Authenticate` and `Proxy-Authorization` apply only to the next hop by their own definitions (§11.7.1, §11.7.2).
- **`Trailer` itself**, which announces a section the recipient has already finished reading.

The broader question — whether a *nameable* field such as `ETag` or `Expires` may be sent in trailers at all (RFC 9110 §6.5.1 permits a trailer field only where the field's own definition does) — is asked of the fields that actually arrive, by `message_trailer_fields_validity`. This rule reads only the declaration.

## Specifications

- [RFC 9110 §6.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.6.2): The `Trailer` field itself: what its value means, and the SHOULD that asks a sender to write one
- [RFC 9110 §A](https://www.rfc-editor.org/rfc/rfc9110.html#appendix-A): The collected grammar, where the list construct is expanded for a sender — the form that shows both that the whole value may be empty and that a member may not
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The sender's half of the list construct. The recipient's half (§5.6.1.2, ignore empty elements) is a different party's requirement and is why the shared list reader is not used here
- [RFC 9110 §5.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.2): Several `Trailer` lines in one field section are one field value, so the members are counted after the lines are joined
- [RFC 9110 §7.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1): `Connection` and hop-by-hop semantics; the sentence that removes connection-options from a trailer section is the MUST behind the nomination finding. This said RFC 7230 §6.1 — the right section of an obsoleted document, with the two notes swapped between them
- [RFC 9110 §6.5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5.1): Limitations on use of trailers. Applied here only to `Trailer` naming itself; the general question is `message_trailer_fields_validity`'s
- [RFC 9112 §7.1.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1.2): The chunked transfer coding's trailer section — HTTP/1.1's framing mechanism for the section this field announces. This said RFC 7230 §4.1.2

## Configuration

```toml
[rules.message_trailer_headers_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good Fields whose own definitions put them in trailers — this one's sender defines it

```http
HTTP/1.1 200 OK
Transfer-Encoding: chunked
Trailer: X-Checksum

<chunked body>
X-Checksum: abc123
```

### ✅ Good A list of no field names is a list; the field is `#field-name`, not `1#field-name`

```http
HTTP/1.1 200 OK
Transfer-Encoding: chunked
Trailer:

<chunked body>
```

### ❌ Bad An empty member — the list construct's sender requirement

```http
HTTP/1.1 200 OK
Transfer-Encoding: chunked
Trailer: X-Checksum,,X-Signature

<chunked body>
```

### ❌ Bad Connection-specific whatever the message says

```http
HTTP/1.1 200 OK
Trailer: Connection

<response body>
```

### ❌ Bad Connection-specific because this message's own `Connection` says so

```http
HTTP/1.1 200 OK
Connection: Keep-Alive
Trailer: Keep-Alive

<response body>
```
