<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Content-Disposition Parameter Validity

Validate that `Content-Disposition` header parameters are syntactically valid and sane. This rule checks common parameters such as `filename`, `filename*` (RFC 5987 ext-value), and `size`. It ensures parameter names are tokens, parameter values are either tokens or valid `quoted-string`s, `filename*` values follow RFC 5987 ext-value syntax, and that parameters are not duplicated within a single header field value.

## Description

`Content-Disposition` parameters provide metadata about how to handle a payload (for example, the suggested filename). Malformed parameters can break user agents or enable confusing behavior. This rule validates parameter name syntax and performs focused checks on common parameters:

- `filename` — must be a `token` or a valid `quoted-string`.
- `filename*` — must be a valid RFC 5987 `ext-value` (e.g., `UTF-8''%e2%82%ac%20rates`).
- `size` — must be a numeric value (digits only), optionally quoted.

When a parameter value is syntactically invalid, the rule raises a `warn`-level violation by default.

## Specifications

- [RFC 6266 §4](https://www.rfc-editor.org/rfc/rfc6266.html#section-4) — Use of `Content-Disposition` in HTTP (parameters, `filename`, `filename*`, `size` notes).
- [RFC 5987 §3.2](https://www.rfc-editor.org/rfc/rfc5987.html#section-3.2) — `ext-value` syntax used for `filename*`.
- [RFC 2616 §2.2 / §3.6](https://www.rfc-editor.org/rfc/rfc2616.html) — `token` and `quoted-string` definitions.

## Configuration

Enable the rule in TOML:

```toml
[rules.message_content_disposition_parameter_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Content-Disposition: attachment; filename="example.txt"
Content-Disposition: attachment; filename*=UTF-8''%e2%82%ac%20rates
Content-Disposition: attachment; filename=example.txt; size=12345
```

### ❌ Bad

```http
Content-Disposition: attachment; filename=unclosed
Content-Disposition: attachment; filename*=UTF-8'%e2%82%ac   ;  # missing second quote
Content-Disposition: attachment; size=12a
Content-Disposition: attachment; filename=foo; filename=bar  # duplicate parameter name
```
