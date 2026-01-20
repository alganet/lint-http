<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_trailer_headers_valid

## Description

Validate `Trailer` header members are syntactically valid header field-names and do not nominate hop-by-hop headers. Trailer members must be `token`-formatted header field-names and MUST NOT be hop-by-hop headers such as `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, or `Upgrade`. When a header is nominated via `Connection`, it is considered hop-by-hop and therefore not appropriate as a trailer member.

## Specifications

- [RFC 7230 §4.1.2 — Connection header and hop-by-hop semantics](https://www.rfc-editor.org/rfc/rfc7230.html#section-4.1.2)
- [RFC 7230 §6.1 — Message framing and trailer fields](https://www.rfc-editor.org/rfc/rfc7230.html#section-6.1)

## Configuration

```toml
[rules.message_trailer_headers_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Trailer: ETag, Expires

<response body>
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Trailer: Connection

<response body>
```

```http
HTTP/1.1 200 OK
Connection: Keep-Alive
Trailer: Keep-Alive

<response body>
```
