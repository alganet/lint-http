<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful Cookie Lifecycle

## Description

Cookies sent by servers via the `Set-Cookie` header establish state
that a client is expected to retain and present on subsequent requests.
This rule reconstructs a simplistic cookie store for a given origin and
verifies that outgoing requests are consistent with that store.  It
flags three broad classes of client misbehaviour:

* Sending cookies after they have clearly expired or been removed.
* Continuing to send an old value after a newer cookie with the same
  name/domain/path has been observed.
* Transmitting a cookie marked `Secure` over an insecure (HTTP) transport.  The rule only flags this if the actual
  name/value pair sent corresponds to a known secure cookie, which avoids
  false positives when a non‑secure cookie with the same name is used.

The check relies solely on the captured traffic for a given client+origin;
if a cookie appears in a request but the linter has never seen it set in the
past, the rule assumes it pre‑dates the capture and does not complain.

## Specifications

- [RFC 6265 §5 — Storage model](https://www.rfc-editor.org/rfc/rfc6265.html#section-5)
- [RFC 6265 §5.1.3 — Domain matching](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.3)
- [RFC 6265 §5.1.4 — Path matching](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.4)

## Configuration

```toml
[rules.stateful_cookie_lifecycle]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
> GET /foo HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Set-Cookie: session=abc; Max-Age=3600; Path=/

> GET /bar HTTP/1.1
> Host: example.com
> Cookie: session=abc
```

### ✅ Good — different non-secure cookie over HTTP

A secure cookie may exist in the store for a broader path, but a more
specific non‑secure cookie with the same name is sent.  No violation should
be raised because the value does not match the secure entry.

```http
> GET / HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Set-Cookie: id=secure; Secure; Path=/

> GET /foo HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Set-Cookie: id=plain; Path=/foo

> GET /foo HTTP/1.1
> Host: example.com
> Cookie: id=plain           # only the non-secure value is sent over HTTP
```
### ❌ Bad — expired cookie sent

```http
> GET /foo HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Set-Cookie: session=abc; Max-Age=1

> GET /bar HTTP/1.1
> Host: example.com
> Cookie: session=abc        # sent five minutes later despite expiration
```

### ❌ Bad — stale value

```http
> GET /foo HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Set-Cookie: id=1; Path=/

< HTTP/1.1 200 OK
< Set-Cookie: id=2; Path=/

> GET /baz HTTP/1.1
> Host: example.com
> Cookie: id=1               # old value should have been replaced
```

### ❌ Bad — secure cookie over HTTP

```http
> GET /login HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Set-Cookie: sid=123; Secure

> GET /dashboard HTTP/1.1
> Host: example.com
> Cookie: sid=123            # insecure transport
```
