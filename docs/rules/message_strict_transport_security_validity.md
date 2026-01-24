<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->
# message_strict_transport_security_validity

Validate `Strict-Transport-Security` header directives follow RFC 6797.

## Description

The `Strict-Transport-Security` response header signals HSTS policies. This rule ensures responses include the required `max-age` directive (a non-negative integer) and that optional directives `includeSubDomains` and `preload` are present without values. Unknown directives are accepted but any value must be a `token` or `quoted-string`. Non-UTF8 header values and syntactic violations are reported as rule violations.

## Specifications

- [RFC 6797 §6.1 — Strict-Transport-Security header](https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1)
- [RFC 6797 §6.1.1 — The max-age Directive](https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1.1)
- [RFC 6797 §6.1.2 — The includeSubDomains Directive](https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1.2)
- Token / quoted-string syntax: [RFC 9110 §5.6.2 — Tokens](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2) and [RFC 9110 §5.6.4 — Quoted Strings](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4)

## Configuration

```toml
[rules.message_strict_transport_security_validity]
enabled = false
severity = "warn"
```

## Examples

### ✅ Good

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

### ✅ Good

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
