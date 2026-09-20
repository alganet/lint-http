<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Retry-After Date or Delay

## Description

The `Retry-After` header, when present in responses, MUST be either a non-negative integer (delay-seconds) or an HTTP-date. This rule flags `Retry-After` values that do not match either form, and flags a repeated `Retry-After` field: the grammar takes a single value, and because the HTTP-date form contains a comma the values cannot be combined into a list. Where the value is a timestamp, the sender's obligation applies: RFC 9110 Section 5.6.7 requires an IMF-fixdate, so one of the two obsolete formats is reported as such, and a weekday its own date does not fall on is reported as such — both under the entries every other dated field reports them under. A value deriving from neither alternative remains this field's own defect.

## Violations

- [field_line_duplicated](../violations/field_line_duplicated.md) — A field is written on more lines than its definition allows
- [http_date_day_name_conflicting](../violations/http_date_day_name_conflicting.md) — Timestamp names a weekday its own date does not fall on
- [http_date_obsolete](../violations/http_date_obsolete.md) — Timestamp is written in an obsolete date format
- [retry_after_malformed](../violations/retry_after_malformed.md) — A Retry-After is neither a date nor a delay

## Specifications

- [RFC 9110 §10.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3): Defines Retry-After generally, with no condition on the status code, then says what it indicates on a 503 and on any 3xx
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order — a sender MUST NOT write multiple field lines of one name, in the headers or the trailers, unless at least one alternative of the field's definition allows the lines to be recombined as a comma-separated list
- [RFC 9110 §5.6.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7): Date/Time Formats — `HTTP-date = IMF-fixdate / obs-date`, the recipient's MUST to accept all three, and the sender's MUST to generate only the first
- [RFC 5322 §3.3](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.3): Date and Time Specification — the semantics § 5.6.7 borrows, including the requirement that a date-time be semantically valid

## Configuration

```toml
[rules.retry_after_date_or_delay]
enabled = true
```

## Examples

### ✅ Good

```http
HTTP/1.1 503 Service Unavailable
Retry-After: 120

HTTP/1.1 503 Service Unavailable
Retry-After: Wed, 21 Oct 2015 07:28:00 GMT
```

### ❌ Bad

```http
HTTP/1.1 503 Service Unavailable
Retry-After: tomorrow

HTTP/1.1 503 Service Unavailable
Retry-After: -1
```

### ❌ Bad a timestamp in a spelling a sender may not generate

```http
HTTP/1.1 503 Service Unavailable
Retry-After: Sunday, 06-Nov-94 08:49:37 GMT

HTTP/1.1 503 Service Unavailable
Retry-After: Sun Nov  6 08:49:37 1994

HTTP/1.1 503 Service Unavailable
Retry-After: Mon, 06 Nov 1994 08:49:37 GMT
```
