<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful Authentication Failure Loop

## Description

Detects repeated `401 Unauthorized` challenges for the same protection space (origin), which strongly indicates an authentication failure loop. When a client continuously retries authentication and repeatedly fails with a 401 across the same origin, it could imply a broken client, misconfigured credentials, or a flawed authentication handshake.

This rule tracks the transaction history by origin and flags if a client receives 4 or more consecutive `401 Unauthorized` challenges without a successful (or other non-401) response in between.

## Specifications

- [RFC 9110 §11.6.2 — 401 Unauthorized](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.2)

## Configuration

```toml
[rules.stateful_authentication_failure_loop]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
> GET /protected HTTP/1.1
> Host: example.com

< 401 Unauthorized HTTP/1.1
< WWW-Authenticate: Basic realm="Access"

> GET /protected HTTP/1.1
> Host: example.com
> Authorization: Basic ...

< 200 OK HTTP/1.1
```

### ❌ Bad — Authentication Loop

```http
> GET /api/v1/data HTTP/1.1
> Host: example.com

< 401 Unauthorized HTTP/1.1
< WWW-Authenticate: Bearer realm="API"

> GET /api/v1/data HTTP/1.1
> Host: example.com
> Authorization: Bearer INVALID

< 401 Unauthorized HTTP/1.1

> GET /api/v1/data HTTP/1.1
> Host: example.com
> Authorization: Bearer INVALID

< 401 Unauthorized HTTP/1.1

> GET /api/v1/data HTTP/1.1
> Host: example.com
> Authorization: Bearer INVALID

< 401 Unauthorized HTTP/1.1
```
