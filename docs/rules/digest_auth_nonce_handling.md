<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Digest Auth Nonce Handling

## Description

Digest authentication relies on a server-provided `nonce` value (and optionally `opaque`) and a client-maintained `nc` (nonce-count) counter to protect against replay attacks.  The client must never reuse a nonce-count for an already-seen nonce, and must return the `opaque` value verbatim.  When a server signals that a nonce is stale (`stale=true` in a subsequent `WWW-Authenticate` challenge), the client is expected to start a new handshake with the fresh nonce, resetting the nonce-count to `00000001`.

This rule ensures that an observed stream of transactions follows these lifecycle expectations by tracking challenges and responses across an origin.

## Violations

- [digest_credentials_challenge_missing](../violations/digest_credentials_challenge_missing.md) — Digest credentials name a nonce no observed challenge offered
- [digest_credentials_nc_invalid](../violations/digest_credentials_nc_invalid.md) — A Digest nonce-count is not the number the exchange calls for
- [digest_credentials_nc_malformed](../violations/digest_credentials_nc_malformed.md) — A Digest nonce-count is not eight hexadecimal digits
- [digest_credentials_opaque_conflicting](../violations/digest_credentials_opaque_conflicting.md) — Digest credentials do not return the opaque the challenge supplied

## Specifications

- [RFC 7616 §3.3](https://www.rfc-editor.org/rfc/rfc7616.html#section-3.3): The WWW-Authenticate Response Header Field — the server challenge, its `nonce` and `opaque` and the case-insensitive `stale` flag a client answers by restarting the count
- [RFC 7616 §3.4](https://www.rfc-editor.org/rfc/rfc7616.html#section-3.4): The Authorization Header Field — the Digest credentials, their parameters, the 4xx consequence for missing or improper ones, the "MUST be used by all implementations" on cnonce and nc, and the two historical-reasons quoting MUSTs enforced in both directions
- [RFC 7616 §3.5](https://www.rfc-editor.org/rfc/rfc7616.html#section-3.5): The Authentication-Info Header Field — where the nc value's width is written down; § 3.4 introduces `nc` as "the hexadecimal count" and never fixes it, and this section requires the field's nc to be the client's, so it is one value with one width

## Configuration

```toml
[rules.digest_auth_nonce_handling]
enabled = true
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
