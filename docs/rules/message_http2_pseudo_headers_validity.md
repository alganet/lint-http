<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Http2 Pseudo Headers Validity

## Description

Validate HTTP/2 request pseudo-header fields. Requests must carry the appropriate fields (e.g., `:method` and `:path` for most requests, `:authority` for CONNECT), and their values are validated for basic syntax (tokens, percent-encoding) to detect malformed or protocol-inconsistent headers. The rule also accepts the asterisk-form (`*`) only when the method is `OPTIONS` (see specifications).

**Nothing here reads the response.** RFC 9113 §8.3.2 requires a response to carry exactly one `:status` pseudo-header field, which the canonical transaction model always supplies as a `u16`, so its absence has no representation to check; and the range that value must fall in is RFC 9110 §15's, which is the same for every HTTP version and is reported by `server_status_code_valid_range`.

## Specifications

- [RFC 9113 §8.3.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1): Request pseudo-header fields — defines `:method`, `:scheme`, `:authority`, and `:path` and their presence/format rules (including `*` for OPTIONS and omitted `:path` for CONNECT)
- [RFC 9113 §8.3.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.2): Response pseudo-header fields — defines the `:status` pseudo-header for responses
- [RFC 9113 §8.5](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.5): CONNECT method — CONNECT requests omit `:scheme` and `:path` and use `:authority` to carry host[:port]

## Configuration

```toml
[rules.message_http2_pseudo_headers_validity]
enabled = true
severity = "error"
```

## Examples

### ✅ Good

```http
:method: GET
:scheme: https
:authority: example.com
:path: /
```

```http
:method: OPTIONS
:path: *
```

### ❌ Bad

```http
:method: GET
```

```http
:method: CONNECT
:authority: example.com:443
:path: /
```
