<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Expires Date Format

## Description

Verifies that the `Expires` response header field (when present) derives from `HTTP-date`, and that a sender generated it in the IMF-fixdate format the specification confines senders to. A value no format parses is not silently ignored by a cache: RFC 9111 §5.3 requires a cache to read it as a time already past, so the response the field was meant to keep fresh is stale on arrival. Which caches read it depends on the rest of the response, and the message says which: beside `max-age` only a cache that does not implement `Cache-Control` reads `Expires` at all, and beside `s-maxage` a shared cache that does implement it ignores the field too.

## Violations

- [expires_malformed](../violations/expires_malformed.md) — Expires derives from no HTTP-date, so a cache reads it as already expired
- [http_date_day_name_conflicting](../violations/http_date_day_name_conflicting.md) — Timestamp names a weekday its own date does not fall on
- [http_date_obsolete](../violations/http_date_obsolete.md) — Timestamp is written in an obsolete date format

## Specifications

- [RFC 9111 §5.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.3): `Expires` — a recipient MUST ignore it when `max-age` is present and a shared cache when `s-maxage` is, an invalid date ("0" above all) MUST be read as already expired, and the field is only intended for recipients that have not implemented Cache-Control
- [RFC 9110 §5.6.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7): Date/Time Formats — `HTTP-date = IMF-fixdate / obs-date`, the recipient's MUST to accept all three, and the sender's MUST to generate only the first
- [RFC 5322 §3.3](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.3): Date and Time Specification — the semantics § 5.6.7 borrows, including the requirement that a date-time be semantically valid

## Configuration

```toml
[rules.expires_date_syntax]
enabled = true
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Date: Wed, 21 Oct 2015 07:28:00 GMT
Expires: Wed, 21 Oct 2015 07:38:00 GMT

Hello
```

### ✅ Good — a leap second is a time of day, and names the midnight after it

```http
HTTP/1.1 200 OK
Date: Sat, 31 Dec 2016 23:59:59 GMT
Expires: Sat, 31 Dec 2016 23:59:60 GMT

Hello
```

### ❌ Bad — a cache reads this as already expired, not as ten minutes

```http
HTTP/1.1 200 OK
Date: Wed, 21 Oct 2015 07:28:00 GMT
Expires: Wed, 21 Oct 2015 07:38:00 UTC

Hello
```

### ❌ Bad — beside max-age only a cache that does not implement Cache-Control reads this, and it reads it as already expired

```http
HTTP/1.1 200 OK
Date: Wed, 21 Oct 2015 07:28:00 GMT
Cache-Control: max-age=600
Expires: Wed, 21 Oct 2015 07:38:00 UTC

Hello
```
