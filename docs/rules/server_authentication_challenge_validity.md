<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# server_authentication_challenge_validity

## Description

Warn when a single response advertises the same `realm` value across multiple
`WWW-Authenticate` authentication schemes. A realm identifies a protection space
and re-using the same realm string for different schemes can cause ambiguity and
confuse credential selection. This is a **heuristic** check (HTTP does not strictly
forbid this pattern), and it is intended to help operators spot potentially
confusing authentication configurations. (RFC 9110 §11.5)

## Specifications

- [RFC 9110 §11.5 — Establishing a Protection Space (Realm)](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.5)
- [RFC 9110 §11.6.1 — WWW-Authenticate](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.1)

## Configuration

Minimal example to enable the rule:

```toml
[rules.server_authentication_challenge_validity]
enabled = true
severity = "warn"
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
