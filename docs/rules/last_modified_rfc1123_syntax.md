<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Last-Modified RFC 1123 Format

## Description

Verifies that the `Last-Modified` header (when present) uses the IMF-fixdate format (a.k.a. RFC 1123 date) as required by HTTP date formatting rules.

## Violations

- [http_date_day_name_conflicting](../violations/http_date_day_name_conflicting.md) — Timestamp names a weekday its own date does not fall on
- [http_date_empty](../violations/http_date_empty.md) — A date field is written with no timestamp on it
- [http_date_malformed](../violations/http_date_malformed.md) — Timestamp derives from no HTTP-date format
- [http_date_obsolete](../violations/http_date_obsolete.md) — Timestamp is written in an obsolete date format

## Specifications

- [RFC 9110 §5.6.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7): Date/Time Formats — `HTTP-date = IMF-fixdate / obs-date`, the recipient's MUST to accept all three, and the sender's MUST to generate only the first
- [RFC 5322 §3.3](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.3): Date and Time Specification — the semantics § 5.6.7 borrows, including the requirement that a date-time be semantically valid

## Configuration

```toml
[rules.last_modified_rfc1123_syntax]
enabled = true
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT
Content-Type: text/plain

Hello
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Last-Modified: 2015-10-21T07:28:00Z
Content-Type: text/plain

Hello
```
