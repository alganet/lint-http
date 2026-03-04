<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful Cookie SameSite Enforcement

## Description

Cookies marked with the `SameSite` attribute impose restrictions on when they
may be included in requests.  `Strict` cookies are only sent in a same-site
context, while `Lax` cookies may also be included on top-level navigations
using safe methods such as `GET`.  `None` cookies have no such restrictions
but must be paired with `Secure` (checked by a different rule).

This rule rebuilds a simple cookie store from prior `Set-Cookie` responses for
a given origin and compares it against the `Cookie` header on outgoing
requests.  If a request includes a cookie whose stored metadata indicates a
`Strict`/`Lax` policy that is violated by the current site relationship and
navigation context, a violation is reported.  Cookies without an explicit
`SameSite` value are treated as `Lax` to reflect modern browser defaults.

The check uses `Sec-Fetch-Site` (and, for Lax decisions, `Sec-Fetch-Mode`)
headers to approximate whether the request is cross-site and whether it
represents a top‑level navigation.

If the relationship cannot be determined (e.g. missing `Sec-Fetch-Site`), the
rule conservatively abstains rather than raising false positives.

## Specifications

- [RFC 6265bis §5.3.4 — SameSite cookie semantics](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#section-5.3.4)
- [Fetch spec Sec-Fetch-Site](https://fetch.spec.whatwg.org/#sec-fetch-site)

## Configuration

```toml
[rules.stateful_cookie_same_site_enforcement]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good — same-site request

```http
> GET /foo HTTP/1.1
> Host: example.com
> Sec-Fetch-Site: same-site
> Cookie: id=1

< HTTP/1.1 200 OK
< Set-Cookie: id=1; SameSite=Strict; Path=/
```

### ✅ Good — Lax cookie sent on top-level navigation

```http
> GET /foo HTTP/1.1
> Host: example.com
> Sec-Fetch-Site: cross-site
> Sec-Fetch-Mode: navigate
> Cookie: sid=abc

< HTTP/1.1 200 OK
< Set-Cookie: sid=abc; SameSite=Lax; Path=/
```

### ❌ Bad — Strict cookie sent cross-site

```http
> GET /resource HTTP/1.1
> Host: example.com
> Sec-Fetch-Site: cross-site
> Cookie: session=xyz

< HTTP/1.1 200 OK
< Set-Cookie: session=xyz; SameSite=Strict; Path=/
```

### ❌ Bad — Lax cookie sent in cross-site subresource request

```http
> GET /image.png HTTP/1.1
> Host: example.com
> Sec-Fetch-Site: cross-site
> Sec-Fetch-Mode: cors
> Cookie: auth=1

< HTTP/1.1 200 OK
< Set-Cookie: auth=1; SameSite=Lax; Path=/
```