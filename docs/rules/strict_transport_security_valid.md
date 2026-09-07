<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Strict Transport Security Valid

## Description

The `Strict-Transport-Security` response header signals HSTS policies. This rule ensures responses include the required `max-age` directive (a non-negative integer) and that optional directives `includeSubDomains` and `preload` are present without values. Unknown directives are accepted but any value must be a `token` or `quoted-string`. Non-UTF8 header values and syntactic violations are reported as rule violations.

## Specifications

- [RFC 6797 §6.1](https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1): Strict-Transport-Security header
- [RFC 6797 §6.1.1](https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1.1): The max-age Directive
- [RFC 6797 §6.1.2](https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1.2): The includeSubDomains Directive
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits
- [RFC 9110 §5.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4): `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` — the two delimiters, the class between them, and the backslash escape

## Configuration

```toml
[rules.strict_transport_security_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

```http
Strict-Transport-Security: max-age=0
```

### ❌ Bad — missing `max-age`

```http
Strict-Transport-Security: includeSubDomains
```

### ❌ Bad — `max-age` not numeric

```http
Strict-Transport-Security: max-age=abc
```

### ❌ Bad — `includeSubDomains` must not have a value

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains=1
```
