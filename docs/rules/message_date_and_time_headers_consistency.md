<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Date and Time Headers Consistency


## Description

Validate that date/time related headers are well-formed and mutually consistent. This rule checks `Date`, `Last-Modified`, `If-Modified-Since`, and `Sunset` for valid IMF-fixdate syntax and simple logical consistency: e.g., `Last-Modified` SHOULD NOT be later than `Date`, `Sunset` SHOULD indicate a future time relative to `Date`, and conditional request `If-Modified-Since` values should not be in the future relative to the request `Date`.

## Specifications

- [RFC 9110 §7.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1.1): `Date` header (IMF-fixdate)
- [RFC 9110 §7.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.7): `Last-Modified` header
- [RFC 9110 §7.8.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8.1): `If-Modified-Since` (conditional requests)
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
