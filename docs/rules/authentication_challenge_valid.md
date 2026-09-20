<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Authentication Challenge Valid

## Description

Warn when a single response advertises the same `realm` value across multiple authentication schemes of one challenge field — `WWW-Authenticate` or `Proxy-Authenticate`, each judged on its own, because § 11.5 makes a protection space the canonical root *and* the realm, so an origin's `realm="x"` and a proxy's `realm="x"` name two spaces rather than one ambiguous one. A realm identifies a protection space and re-using the same realm string for different schemes can cause ambiguity and confuse credential selection. This is a **heuristic** check (HTTP does not strictly forbid this pattern), and it is intended to help operators spot potentially confusing authentication configurations. (RFC 9110 §11.5)

## Violations

- [challenge_realm_ambiguous](../violations/challenge_realm_ambiguous.md) — One realm is advertised by two authentication schemes

## Specifications

- [RFC 9110 §11.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.5): Establishing a Protection Space (Realm) — a realm names one protection space, each with its own authentication scheme, and a response may carry several challenges of one scheme with different realms; the section closes by admitting one spelling of the value
- [RFC 9110 §11.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.1): WWW-Authenticate

## Configuration

```toml
[rules.authentication_challenge_valid]
enabled = true
```

## Examples

### ✅ Good

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="users"
```

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: NewScheme realm="admin"
```

### ❌ Bad

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="shared"
WWW-Authenticate: NewScheme realm="shared"
```

### ❌ Bad (the other field § 11 writes as `#challenge`)

```http
HTTP/1.1 407 Proxy Authentication Required
Proxy-Authenticate: Basic realm="shared"
Proxy-Authenticate: NewScheme realm="shared"
```

### ✅ Good (one realm string, two protection spaces: § 11.5 defines a space by its root as well as its realm)

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="shared"
Proxy-Authenticate: Digest realm="shared"
```
