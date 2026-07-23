<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Date and Time Headers Consistency

## Description

Validate that date/time related headers are well-formed and mutually consistent. Each header is parsed as an HTTP-date (a recipient accepts all three formats; the sender-only IMF-fixdate obligation is checked by the per-header format rules), then compared: `Last-Modified` MUST NOT be later than `Date` (RFC 9110 §8.8.2.1), `Sunset` SHOULD indicate a future time relative to `Date` (RFC 8594 §3), and — as a reasonableness check with no direct spec basis — a conditional-request `If-Modified-Since` should not be later than the request's own `Date`. A small clock-skew tolerance is allowed. Values that are not a parseable HTTP-date, or that contain non-UTF8 bytes, are flagged.

## Specifications

- [RFC 9110 §6.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.6.1): `Date` header (parsed as HTTP-date for comparison)
- [RFC 9110 §8.8.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2): `Last-Modified` header
- [RFC 9110 §13.1.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.3): `If-Modified-Since` (conditional requests)
- [RFC 8594 §3](https://www.rfc-editor.org/rfc/rfc8594.html#section-3): `Sunset` header semantics

## Configuration

```toml
[rules.message_date_and_time_headers_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Date: Wed, 21 Oct 2015 07:28:00 GMT
Last-Modified: Wed, 21 Oct 2015 07:20:00 GMT
Sunset: Tue, 01 Jan 2030 00:00:00 GMT
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Date: Wed, 21 Oct 2015 07:28:00 GMT
Last-Modified: Wed, 21 Oct 2015 07:30:00 GMT  # Last-Modified after Date
Sunset: Wed, 21 Oct 2015 07:27:00 GMT        # Sunset is in the past relative to Date
```
