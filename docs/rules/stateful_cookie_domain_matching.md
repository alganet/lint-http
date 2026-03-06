<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful Cookie Domain Matching

## Description

A client should only send a cookie back to a server when the request URI
satisfies the cookie's domain and path constraints.  Browsers follow the
matching algorithm in [RFC 6265 §5.1.3](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.3)
and §5.1.4 when deciding which cookies to include with a request; this rule
flags instances where the observed `Cookie` header contains a name/value pair
that corresponds to a previously set cookie whose attributes would *not*
allow it to be sent for the current host/path.

To avoid spurious warnings the check only considers cookies that have been
seen in the capture history and matches on the exact value.  Unknown cookies
are assumed to pre‑date the capture and are ignored.  The related
`stateful_cookie_lifecycle` rule already handles path‑mismatch diagnostics and
secure‑cookie checks; this rule is primarily intended to catch domain
mismatches that the other rule overlooks.

## Specifications

- [RFC 6265 §5.1.3 — Domain matching](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.3)
- [RFC 6265 §5.1.4 — Path matching](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.4)

## Configuration

```toml
[rules.stateful_cookie_domain_matching]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

A cookie that was set for `example.com` is only sent back to that host.

```http
> GET / HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Set-Cookie: session=abc; Path=/

> GET /foo HTTP/1.1
> Host: example.com
> Cookie: session=abc
```

### ❌ Bad — domain mismatch

The client attempts to send a cookie that was recorded for *another* host.

```http
> GET / HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Set-Cookie: sid=123; Domain=example.com

> GET / HTTP/1.1
> Host: other.com
> Cookie: sid=123               # invalid; domain does not match
```

### ❌ Bad — path mismatch (also flagged by stateful_cookie_lifecycle)

```
> GET / HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Set-Cookie: id=1; Path=/private

> GET /public HTTP/1.1
> Host: example.com
> Cookie: id=1                 # path does not match
```
