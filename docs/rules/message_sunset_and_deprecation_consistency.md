<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Sunset and Deprecation Consistency

## Description

When both `Sunset` and `Deprecation` response headers are present, they should be logically consistent: `Deprecation` indicates when a resource was (or will be) deprecated and `Sunset` indicates the removal/shutdown date. This rule validates that, when both headers are parseable, the `Deprecation` timestamp is not later than the `Sunset` date. Additionally, the rule validates the `Sunset` header syntax: if a `Sunset` header is present but not a valid IMF-fixdate, the rule reports a violation (the `Sunset` header must be a valid IMF-fixdate per RFC 8594), even when `Deprecation` is absent.

## Specifications

- [RFC 8594 §3](https://www.rfc-editor.org/rfc/rfc8594.html#section-3): `Sunset` header semantics (IMF-fixdate)
- [RFC 9745 §2](https://www.rfc-editor.org/rfc/rfc9745.html#section-2): `Deprecation` structured Date item (`@<seconds>`) and legacy forms
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
