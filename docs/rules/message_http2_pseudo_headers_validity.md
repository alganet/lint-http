<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_http2_pseudo_headers_validity

## Description

Validate HTTP/2 pseudo-header fields used in requests and responses. Requests that include pseudo-headers must include the appropriate fields (e.g., `:method` and `:path` for most requests, `:authority` for CONNECT), and response pseudo-headers must be limited to `:status`. Values are validated for basic syntax (tokens, percent-encoding, numeric status) to detect malformed or protocol-inconsistent headers. The rule also accepts the asterisk-form (`*`) only when the method is `OPTIONS` (see specifications).

## Specifications

- [RFC 9113 §8.3.1 — Request pseudo-header fields](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1) — defines `:method`, `:scheme`, `:authority`, and `:path` and their presence/format rules (including `*` for OPTIONS and omitted `:path` for CONNECT).
- [RFC 9113 §8.3.2 — Response pseudo-header fields](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.2) — defines the `:status` pseudo-header for responses.
- [RFC 9113 §8.5 — CONNECT method](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.5) — CONNECT requests omit `:scheme` and `:path` and use `:authority` to carry host[:port].

## Configuration

```toml
[rules.message_http2_pseudo_headers_validity]
enabled = true
severity = "error"
```

## Examples

### ✅ Good

Request with required pseudo-headers:

```http
:method: GET
:scheme: https
:authority: example.com
:path: /
```

OPTIONS using asterisk-form (allowed):

```http
:method: OPTIONS
:path: *
```

Response with valid :status:

```http
:status: 200
```

### ❌ Bad

Missing :path in non-CONNECT request:

```http
:method: GET
```

Response with non-numeric :status:

```http
:status: OK
```

CONNECT with a path (not allowed):

```http
:method: CONNECT
:authority: example.com:443
:path: /
```

---
