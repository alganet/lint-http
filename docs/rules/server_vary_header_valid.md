<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Vary Header Valid

## Description

Validate the `Vary` response header. This rule enforces that:

- When present, `Vary` MUST be either `*` or a comma-separated list of header field-names.
- Each field-name must conform to the `token` grammar (RFC `tchar`).
- `*` MUST NOT be combined with other field-names (across the header value or multiple header fields).

## Specifications

- [RFC 9110 §7.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.3.6) — Vary header

## Configuration

```toml
[rules.server_vary_header_valid]
enabled = true
severity = "warn"
```

## Examples

✅ Good

```http
Vary: Accept-Encoding
Vary: User-Agent
```
✅ Good

```http
Vary: Accept-Encoding, User-Agent
```

✅ Good

```http
Vary: *
```

❌ Bad

```http
Vary: *, Accept-Encoding   # '*' must not be combined with other field-names
Vary: x@bad                # invalid token characters in field-name
Vary:                      # empty header value is invalid
```
