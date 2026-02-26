<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful Digest Auth Nonce Handling

## Description

Digest authentication relies on a server-provided `nonce` value (and
optionally `opaque`) and a client-maintained `nc` (nonce-count) counter to
protect against replay attacks.  The client must never reuse a nonce-count for
an already-seen nonce, and must return the `opaque` value verbatim.  When a
server signals that a nonce is stale (`stale=true` in a subsequent
`WWW-Authenticate` challenge), the client is expected to start a new handshake
with the fresh nonce, resetting the nonce-count to `00000001`.

This rule ensures that an observed stream of transactions follows these
lifecycle expectations by tracking challenges and responses across an origin.

## Specifications

- [RFC 7616 §3.2.1 — Server challenge syntax](https://www.rfc-editor.org/rfc/rfc7616.html#section-3.2.1)
- [RFC 7616 §3.2.2 — Client response parameters (`nonce`, `nc`, `opaque`)](https://www.rfc-editor.org/rfc/rfc7616.html#section-3.2.2)

## Configuration

```toml
[rules.stateful_digest_auth_nonce_handling]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good – basic progression

```http
> GET /resource HTTP/1.1
> Host: example.com

< 401 Unauthorized HTTP/1.1
< WWW-Authenticate: Digest realm="r", nonce="n1", opaque="o"

> GET /resource HTTP/1.1
> Host: example.com
> Authorization: Digest username="u", realm="r", nonce="n1", nc=00000001, uri="/resource", response="...", opaque="o"

< 200 OK HTTP/1.1

> GET /other HTTP/1.1
> Host: example.com
> Authorization: Digest username="u", realm="r", nonce="n1", nc=00000002, uri="/other", response="...", opaque="o"
```

### ❌ Bad – missing challenge

```http
> GET /resource HTTP/1.1
> Host: example.com
> Authorization: Digest username="u", realm="r", nonce="n1", nc=00000001, uri="/resource", response="..."
```

### ❌ Bad – opaque mismatch

```http
< 401 Unauthorized HTTP/1.1
< WWW-Authenticate: Digest realm="r", nonce="n", opaque="o"

> GET /resource HTTP/1.1
> Host: example.com
> Authorization: Digest username="u", realm="r", nonce="n", nc=00000001, uri="/resource", response="...", opaque="bad"
```

### ❌ Bad – nonce-count regression

```http
< 401 Unauthorized HTTP/1.1
< WWW-Authenticate: Digest realm="r", nonce="n"

> GET /a HTTP/1.1
> Host: example.com
> Authorization: Digest username="u", realm="r", nonce="n", nc=00000005, uri="/a", response="..."

> GET /b HTTP/1.1
> Host: example.com
> Authorization: Digest username="u", realm="r", nonce="n", nc=00000004, uri="/b", response="..."
```

### ❌ Bad – stale nonce but counter not reset

```http
< 401 Unauthorized HTTP/1.1
< WWW-Authenticate: Digest realm="r", nonce="n2", stale=true

> GET /x HTTP/1.1
> Host: example.com
> Authorization: Digest username="u", realm="r", nonce="n2", nc=00000005, uri="/x", response="..."
```
