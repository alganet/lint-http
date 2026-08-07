<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Range And Content Range Consistency

## Description

Validate the semantics and syntax of `Range` (request) and `Content-Range` (response) interactions.

**A 206 carrying a single part** MUST include a `Content-Range` describing the enclosed range, and `Content-Length` (when present) must equal that range's length.

**A 206 carrying multiple parts** is the opposite case, and RFC 9110 §15.3.7.2 is explicit about it: the parts each carry their own `Content-Range` and the header section MUST NOT carry one. A response whose `Content-Type` is `multipart/byteranges` is therefore checked for the *presence* of the field rather than its absence — and, since a client that asked for one range may not be able to read a multipart response, for having been sent to a request that asked for more than one. What is inside the parts is message content, which this rule does not read.

**A 416** (Range Not Satisfiable) is the rejection of the ranges in the request's `Range` field. To a *byte*-range request it should carry `Content-Range: bytes */<complete-length>`; both sentences asking for that field say SHOULD and both say it of byte ranges only, so its absence is not reported for other units. A `Content-Range` the server did send is checked whatever the unit: a 416 encloses no part, so the satisfied form cannot be what it means.

A 206 or a 416 whose request carried no `Range` at all contradicts the status code's own definition, and is reported whatever the response's `Content-Range` says.

**Not this rule's findings:** a malformed `Content-Length` belongs to `message_content_length`, which owns that field's syntax on both sides — this rule declines rather than reporting it a second time; a `Range` value that is not a `ranges-specifier` belongs to `client_range_header_syntax_valid`, and leaves this rule knowing less rather than guessing.

## Specifications

- [RFC 9110 §15.3.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7): 206 Partial Content: single-part 206 responses MUST include a `Content-Range` header describing the enclosed range
- [RFC 9110 §15.3.7.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7.2): 206 Partial Content, multiple parts: the parts carry the `Content-Range` fields and the header section MUST NOT carry one; a request for a single range MUST NOT be answered with a multipart response
- [RFC 9110 §14.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.4): Content-Range: syntax of `Content-Range` and the semantics for satisfied and unsatisfiable ranges
- [RFC 9110 §15.5.17](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.17): 416 Range Not Satisfiable: the status code is the rejection of the ranges in the request's `Range` field; a server answering a *byte*-range request SHOULD include `Content-Range: bytes */<complete-length>`

## Configuration

```toml
[rules.message_range_and_content_range_consistency]
enabled = true
severity = "warn"
# Range units whose first-pos/last-pos may be read as octet offsets and checked
# against Content-Length. Units are an extensible token set (RFC 9110 14.1); a
# Content-Range naming a unit not listed here is still parsed and structurally
# validated, but its length is not compared to Content-Length.
# Only "bytes" is licensed by the specification: RFC 9110 14.1.2 defines its
# positions as inclusive, zero-based octet offsets, which is what makes
# last - first + 1 an octet count. Adding another unit here is you asserting
# the same of it.
units = ["bytes"]
```

## Examples

### ✅ Good

```http
GET /resource HTTP/1.1
Host: example.com
Range: bytes=0-499

HTTP/1.1 206 Partial Content
Content-Range: bytes 0-499/1234
Content-Length: 500
Content-Type: application/octet-stream

...500 bytes...
```

### ❌ Bad

```http
GET /resource HTTP/1.1
Host: example.com
Range: bytes=0-499

HTTP/1.1 206 Partial Content
Content-Length: 500

...500 bytes but missing Content-Range in headers...
```

```http
GET /resource HTTP/1.1
Host: example.com

HTTP/1.1 206 Partial Content
Content-Range: bytes 0-1/10

# 206 must not be sent if the request did not include a Range header
```

### ✅ Good (multiple parts: each body part carries its own Content-Range)

```http
GET /resource HTTP/1.1
Host: example.com
Range: bytes=500-999,7000-7999

HTTP/1.1 206 Partial Content
Content-Type: multipart/byteranges; boundary=THIS_STRING_SEPARATES
Content-Length: 1741

...the parts, each with its own Content-Range...
```

### ❌ Bad — a multipart 206 must not carry Content-Range in its header section

```http
GET /resource HTTP/1.1
Host: example.com
Range: bytes=500-999,7000-7999

HTTP/1.1 206 Partial Content
Content-Type: multipart/byteranges; boundary=THIS_STRING_SEPARATES
Content-Range: bytes 500-999/8000

...the parts...
```

### ❌ Bad — 416 uses the "*/complete-length" unsatisfied-range form

```http
GET /resource HTTP/1.1
Host: example.com
Range: bytes=99999-

HTTP/1.1 416 Range Not Satisfiable
Content-Range: bytes 0-1/10

# the form above describes an enclosed range, and a 416 encloses none
```
