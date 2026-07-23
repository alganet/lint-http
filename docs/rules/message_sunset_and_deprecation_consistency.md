<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Sunset and Deprecation Consistency

## Description

When both `Sunset` and `Deprecation` response headers are present they must be logically consistent: `Deprecation` (a Structured Field Date, `@<seconds>`, RFC 9745 §2.1) marks when a resource was or will be deprecated, and `Sunset` (an HTTP-date, RFC 8594 §3) marks the removal date. RFC 9745 §4 requires that the Sunset timestamp not be earlier than the Deprecation timestamp; this rule flags the reverse (subject to a small clock-skew tolerance). It also validates the `Sunset` syntax: a `Sunset` header that is not a parseable HTTP-date is reported even when `Deprecation` is absent. Legacy/non-structured `Deprecation` forms are left to `server_deprecation_header_syntax`.

## Specifications

- [RFC 8594 §3](https://www.rfc-editor.org/rfc/rfc8594.html#section-3): `Sunset` header semantics (HTTP-date)
- [RFC 9745 §2.1](https://www.rfc-editor.org/rfc/rfc9745.html#section-2.1): `Deprecation` is a Structured Field Date (`@<seconds>`)
- [RFC 9745 §4](https://www.rfc-editor.org/rfc/rfc9745.html#section-4): Sunset MUST NOT be earlier than Deprecation
- [RFC 9651 §3.3.7](https://www.rfc-editor.org/rfc/rfc9651.html#section-3.3.7): Structured Field `Date` item syntax

## Configuration

```toml
[rules.message_sunset_and_deprecation_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Date: Wed, 21 Oct 2025 07:28:00 GMT
Deprecation: @1730000000
Sunset: Tue, 01 Jan 2030 00:00:00 GMT
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Date: Wed, 21 Oct 2025 07:28:00 GMT
Deprecation: @4102444800   # year 2100
Sunset: Tue, 01 Jan 2030 00:00:00 GMT
```
