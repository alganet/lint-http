<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Request Body Length Accuracy

## Description

Checks that a request's `Content-Length` matches the number of body octets actually observed. RFC 9112 §6.2 makes that number the framing — "the Content-Length field value provides the framing information necessary for determining where the data (and message) ends" — and §6.3 says a recipient that does not receive that many octets "MUST consider the message to be incomplete and close the connection". A mismatch is that message.

**Only when there is no `Transfer-Encoding`.** §6.3 licenses the comparison in exactly those terms: "If a valid Content-Length header field is present *without Transfer-Encoding*, its decimal value defines the expected message body length in octets." When both fields are present the Transfer-Encoding overrides, and the declared length is a number the specification says to disregard — so this rule stays silent. Sending both is its own MUST NOT (§6.2) and `message_content_length_vs_transfer_encoding` reports it.

**Syntax belongs to another rule.** A `Content-Length` that is not a valid `1*DIGIT` — or whose field lines disagree, or which no integer can represent — leaves no number to compare, so this rule declines and `message_content_length` reports it. That rule is also where §6.3's comma-list allowance lives: `Content-Length: 3, 3` is one value of three, not a malformed field.

**What the comparison is against.** The recorded length counts the octets that streamed through with the transfer coding resolved and any `Content-Encoding` left encoded — which is what `Content-Length` counts too, so the two are directly comparable. Where no body was captured, nothing is claimed.

## Specifications

- [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3): Message body length — item 6 is what licenses this rule at all, and its condition is 'without Transfer-Encoding'; item 3 is why a message carrying both is measured by neither
- [RFC 9112 §6.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.2): Content-Length as framing — why a mismatch matters rather than merely differing. Also the MUST NOT against sending it beside Transfer-Encoding, which is another rule's finding
- [RFC 9110 §8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6): Where the field and its `1*DIGIT` grammar are actually defined — the syntax itself is `message_content_length`'s subject, not this rule's

## Configuration

```toml
[rules.message_request_body_length_accuracy]
enabled = true
severity = "error"
```

## Examples

### ✅ Good

```http
POST /upload HTTP/1.1
Host: example.com
Content-Length: 3

abc
```

### ✅ Good (a comma list of equal values is one value)

```http
POST /upload HTTP/1.1
Host: example.com
Content-Length: 3, 3

abc
```

### ✅ Good (Transfer-Encoding overrides, so nothing here is measured)

```http
POST /upload HTTP/1.1
Host: example.com
Content-Length: 10
Transfer-Encoding: chunked

abc
```

### ❌ Bad (the request is incomplete)

```http
POST /upload HTTP/1.1
Host: example.com
Content-Length: 10

abc
```
