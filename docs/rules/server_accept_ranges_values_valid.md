<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Accept-Ranges Values Valid

## Description

Validate the `Accept-Ranges` response header. This rule enforces that:

- When present, `Accept-Ranges` MUST contain only registered `range-unit` tokens.
- For practical compatibility, this rule accepts `bytes` (the common range-unit) or `none` only.
- The `none` token MUST NOT be combined with other range-units.

## Specifications

- [RFC 9110 §7.3.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.3.4) — Accept-Ranges header

## Configuration

```toml
[rules.server_accept_ranges_values_valid]
enabled = true
severity = "warn"
```

## Examples

✅ Good

```http
Accept-Ranges: bytes
Accept-Ranges: none
Accept-Ranges: bytes, bytes
```

❌ Bad

```http
Accept-Ranges: none, bytes
Accept-Ranges: foobar
Accept-Ranges: b ytes
```