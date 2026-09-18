<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Date and Time Headers Consistency

## Description

Validate that date/time related headers are well-formed and mutually consistent. Each header is parsed as an HTTP-date (a recipient accepts all three formats), and at the two fields this rule owns the reading of — `Date` and `Sunset` — the sender-only IMF-fixdate obligation is read here too, because neither field has a per-header format rule to leave it to; everywhere else it belongs to that rule, then compared: `Last-Modified` MUST NOT be later than `Date` (RFC 9110 §8.8.2.1), `Sunset` SHOULD indicate a future time relative to `Date` (RFC 8594 §3), and — as a reasonableness check with no direct spec basis — a conditional-request `If-Modified-Since` should not be later than the request's own `Date`. A small clock-skew tolerance is allowed. A value that is not a parseable HTTP-date is flagged for the field this rule owns the reading of — `Date` and `Sunset` — and left to the per-field format rule otherwise. The value is read as octets: every octet an HTTP-date prints is visible US-ASCII in all three formats, so a field line no string reader accepts is one no format accepts, and it is reported as the timestamp defect it is.

## Violations

- [conditional_date_conflicting](../violations/conditional_date_conflicting.md) — A date precondition names a time after the request's own Date
- [date_missing](../violations/date_missing.md) — A response does not say when it was written
- [http_date_day_name_conflicting](../violations/http_date_day_name_conflicting.md) — Timestamp names a weekday its own date does not fall on
- [http_date_empty](../violations/http_date_empty.md) — A date field is written with no timestamp on it
- [http_date_malformed](../violations/http_date_malformed.md) — Timestamp derives from no HTTP-date format
- [http_date_obsolete](../violations/http_date_obsolete.md) — Timestamp is written in an obsolete date format
- [last_modified_conflicting](../violations/last_modified_conflicting.md) — A Last-Modified is later than the Date beside it
- [sunset_invalid](../violations/sunset_invalid.md) — A Sunset names a time that has already passed

## Specifications

- [RFC 9110 §6.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.6.1): `Date` — when the message was originated, who must generate it, who must not, and what a recipient does when it is absent
- [RFC 9110 §8.8.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2): `Last-Modified` header
- [RFC 9110 §13.1.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.3): `If-Modified-Since` (conditional requests)
- [RFC 8594 §3](https://www.rfc-editor.org/rfc/rfc8594.html#section-3): The `Sunset` HTTP header field — an `HTTP-date` timestamp that SHOULD be in the future
- [RFC 9110 §5.6.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7): Date/Time Formats — `HTTP-date = IMF-fixdate / obs-date`, the recipient's MUST to accept all three, and the sender's MUST to generate only the first
- [RFC 9110 §8.8.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2.1): Generation — an origin server with a clock MUST NOT generate a `Last-Modified` date later than its own `Date`
- [RFC 5322 §3.3](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.3): Date and Time Specification — the semantics § 5.6.7 borrows, including the requirement that a date-time be semantically valid

## Configuration

```toml
[rules.date_and_time_headers_consistent]
enabled = true
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

### ❌ Bad — the weekday and the date name different days; 21 Oct 2015 was a Wednesday

```http
HTTP/1.1 200 OK
Date: Mon, 21 Oct 2015 07:28:00 GMT
```

### ❌ Bad — a 200 that never says when it was written

```http
HTTP/1.1 200 OK
Content-Type: text/html;charset=utf-8
```

### ❌ Bad — an RFC 850 timestamp: every recipient must read it, and no sender may write it

```http
HTTP/1.1 200 OK
Date: Sunday, 06-Nov-94 08:49:37 GMT
```
