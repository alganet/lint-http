<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_te_header_constraints

## Description

Validate the `TE` request header for syntax and usage:

- Each member must be either the literal `trailers` or a transfer-coding token with optional parameters.
- `q` (quality) parameter, if present, must be a valid qvalue between `0` and `1` with up to three decimals (e.g., `0.8`, `0.123`, `1.0`).
- Parameter values must be a `token` or a `quoted-string`.
- If a request includes a `TE` header, the `Connection` header MUST include the `TE` token.
- `TE` MUST NOT appear in responses.

## Specifications

- [RFC 9110 §10.1.4](https://www.rfc-editor.org/rfc/rfc9110#section-10.1.4) — TE header
- [RFC 9110 §6.5.1](https://www.rfc-editor.org/rfc/rfc9110#section-6.5.1) — Limitations on trailers

## Configuration

Enable the rule in TOML:

```toml
[rules.message_te_header_constraints]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```
GET /resource HTTP/1.1
Host: example.com
Connection: TE
TE: trailers
```

### ✅ Good (chunked listed in TE with quality)

```
GET /resource HTTP/1.1
Host: example.com
Connection: keep-alive, TE
TE: chunked;q=0.8
```

### ❌ Bad (TE without Connection: TE)

```
GET /resource HTTP/1.1
Host: example.com
TE: chunked;q=0.8
```

### ❌ Bad (invalid token)

```
GET /resource HTTP/1.1
Host: example.com
Connection: TE
TE: x!bad
```

### ❌ Bad (TE in response)

```
HTTP/1.1 200 OK
TE: trailers
```
