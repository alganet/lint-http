<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Range And Content Range Consistency

## Description

Validate the semantics and syntax of `Range` (request) and `Content-Range` (response) interactions.

**A 206 carrying a single part** MUST include a `Content-Range` describing the enclosed range, and `Content-Length` (when present) must equal that range's length.

**A 206 carrying multiple parts** is the opposite case, and RFC 9110 §15.3.7.2 is explicit about it: the parts each carry their own `Content-Range` and the header section MUST NOT carry one. A response whose `Content-Type` is `multipart/byteranges` is therefore checked for the *presence* of the field rather than its absence — and, since a client that asked for one range may not be able to read a multipart response, for having been sent to a request that asked for more than one. What is inside the parts is message content, which this rule does not read.

**A 416** (Range Not Satisfiable) must include an unsatisfiable `Content-Range` (`bytes */<length>`).

A 206 whose request carried no `Range` at all contradicts the status code's own definition, and is reported whatever its `Content-Range` says.

**Not this rule's finding:** a `Range` value that is not a `ranges-specifier` belongs to `client_range_header_syntax_valid`, and leaves this rule knowing less rather than guessing.

## Specifications

- [RFC 9110 §15.3.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7): 206 Partial Content: single-part 206 responses MUST include a `Content-Range` header describing the enclosed range
- [RFC 9110 §15.3.7.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7.2): 206 Partial Content, multiple parts: the parts carry the `Content-Range` fields and the header section MUST NOT carry one; a request for a single range MUST NOT be answered with a multipart response
- [RFC 9110 §14.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.4): Content-Range: syntax of `Content-Range` and the semantics for satisfied and unsatisfiable ranges
- [RFC 9110 §15.5.17](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.17): 416 Range Not Satisfiable: server SHOULD include `Content-Range: bytes */<complete-length>` in 416 responses

## Configuration

```toml
[rules.message_range_and_content_range_consistency]
enabled = true
severity = "warn"
# Range units whose first-pos/last-pos may be read as octet offsets and checked
# against Content-Length. Units are an extensible token set (RFC 9110 14.1); a
# Content-Range naming a unit not listed here is still parsed and structurally
# validated, but its length is not compared to Content-Length.
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

```http
HTTP/1.1 416 Range Not Satisfiable
Content-Range: bytes 0-1/10

# 416 must use a "*/length" unsatisfied-range form
```
