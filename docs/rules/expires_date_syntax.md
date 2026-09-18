<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Expires Date Format

## Description

Verifies that the `Expires` response header field (when present) derives from `HTTP-date`, and that a sender generated it in the IMF-fixdate format the specification confines senders to. A value no format parses is not silently ignored by a cache: RFC 9111 §5.3 requires every cache to read it as a time already past, so the response the field was meant to keep fresh is stale on arrival.

## Violations

- [expires_malformed](../violations/expires_malformed.md) — Expires derives from no HTTP-date, so a cache reads it as already expired
- [http_date_obsolete](../violations/http_date_obsolete.md) — Timestamp is written in an obsolete date format

## Specifications

- [RFC 9111 §5.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.3): `Expires` — a recipient MUST ignore it when `max-age` is present and a shared cache when `s-maxage` is, an invalid date ("0" above all) MUST be read as already expired, and the field is only intended for recipients that have not implemented Cache-Control
- [RFC 9110 §5.6.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7): Date/Time Formats — `HTTP-date = IMF-fixdate / obs-date`, the recipient's MUST to accept all three, and the sender's MUST to generate only the first

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

### ❌ Bad — a cache reads this as already expired, not as ten minutes

```http
HTTP/1.1 200 OK
Date: Wed, 21 Oct 2015 07:28:00 GMT
Expires: Wed, 21 Oct 2015 07:38:00 UTC

Hello
```
