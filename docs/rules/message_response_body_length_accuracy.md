<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Response Body Length Accuracy

## Description

Checks that a response's `Content-Length` matches the number of body octets actually observed. RFC 9112 §6.2 makes that value the framing — "necessary for determining where the data (and message) ends" — and RFC 9110 §8.6 says why a proxy in particular must care: "a sender MUST NOT forward a message with a Content-Length header field value that is known to be incorrect". A length that disagrees with the framing is how response splitting reaches the next hop.

**RFC 9112 §6.3 lists eight ways a body length is determined, in precedence order, and this rule is item 6.** The items above it are the reason most of what follows is an exemption rather than a check:

- *Item 1* — a response to `HEAD`, and any `1xx`, `204` or `304`, ends at the blank line "regardless of the header fields present". Its `Content-Length` describes a body that was deliberately not sent: §8.6 requires, in a MUST, that a HEAD response's value equal what a `GET` would have returned, and a 304's equal what a `200` would have. Comparing either against zero captured octets reports a conforming response, so these are not measured here. Whether the value matches what a GET *would* have returned needs two transactions; `semantic_head_response_headers_match_get` has them.
- *Item 2* — a `2xx` to `CONNECT` becomes a tunnel, and a client "MUST ignore any Content-Length or Transfer-Encoding header fields received in such a message".
- *Item 3* — when `Transfer-Encoding` is also present it overrides, so the declared length is disregarded. Carrying both is its own MUST NOT (§6.2) and `message_content_length_vs_transfer_encoding` reports it.
- *Item 8* — a response with no declared length is close-delimited; there is nothing to compare.

**Syntax belongs to another rule.** A value that is not `1*DIGIT`, or whose field lines disagree, leaves no number to compare, so this rule declines and `message_content_length` reports it. That rule also implements §6.3's allowance for `Content-Length: 42, 42` — a comma list of equal values is one value, not a malformed field.

**What the comparison is against.** The recorded length counts octets that streamed through with the transfer coding resolved and any `Content-Encoding` left encoded — which is what `Content-Length` counts. Where no body was captured, nothing is claimed.

## Specifications

- [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3): Message body length, in precedence order — this rule is item 6, and items 1, 2 and 3 are why most responses are exempt rather than checked
- [RFC 9110 §8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6): Content-Length: the field, its grammar, the MUSTs that make a HEAD or 304 response's value describe a body it did not send, and the MUST NOT against forwarding a value known to be incorrect — this rule's reason to exist
- [RFC 9112 §6.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.2): Content-Length as framing, and the MUST NOT against sending it beside Transfer-Encoding — another rule's finding
- [RFC 9110 §9.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2): HEAD — servers SHOULD answer it with the fields they would have sent for GET, which is what made the exemption the common case rather than a corner

## Configuration

```toml
[rules.message_response_body_length_accuracy]
enabled = true
severity = "error"
```

## Examples

### ✅ Good

```http
GET /x HTTP/1.1

HTTP/1.1 200 OK
Content-Length: 3

abc
```

### ✅ Good (a HEAD response declares what a GET would have returned)

```http
HEAD /large.iso HTTP/1.1

HTTP/1.1 200 OK
Content-Length: 1048576
```

### ✅ Good (304 declares what a 200 would have returned)

```http
GET /x HTTP/1.1

HTTP/1.1 304 Not Modified
Content-Length: 1024
```

### ✅ Good (Transfer-Encoding overrides, so nothing here is measured)

```http
GET /x HTTP/1.1

HTTP/1.1 200 OK
Content-Length: 10
Transfer-Encoding: chunked

abc
```

### ❌ Bad (the response is incomplete, and must not be forwarded)

```http
GET /x HTTP/1.1

HTTP/1.1 200 OK
Content-Length: 10

abc
```
