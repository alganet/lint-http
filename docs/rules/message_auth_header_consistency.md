<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->
# message_auth_header_consistency

## Description

This rule validates basic consistency of HTTP authentication headers. It performs the following checks:

- Detects duplicated auth-params within a single `WWW-Authenticate` challenge (e.g., repeated `realm`) which is likely a server bug.
- Detects conflicting `realm` values for repeated challenges of the same auth-scheme in the same response (e.g., two `Basic` challenges advertising different realms).
- When a request contains `Authorization` and a preceding response (e.g., a `401`/`407`) is available, ensures the request's auth-scheme was advertised by the previous response's `WWW-Authenticate` challenges.

These checks help catch misconfigurations and confusing server/client interactions that break authentication flows.

## Specifications

- [RFC 9110 §7.2.1 — WWW-Authenticate](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2.1)
- [RFC 9110 §7.2.2 — Authorization](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2.2)
- [RFC 7235 §2.1 — Challenge and `token68`](https://www.rfc-editor.org/rfc/rfc7235.html#section-2.1)

## Configuration

Minimal example to enable the rule:

```toml
[rules.message_auth_header_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="example"
```

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="example", NewScheme abcdef=
```

```http
# Client following 401 with the same advertised scheme
Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
```

### ❌ Bad

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="a"
WWW-Authenticate: Basic realm="b"
```

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="x", realm="y"
```

```http
# Client sends Authorization using a scheme the server did not advertise in previous 401
Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
# previous response: 401 WWW-Authenticate: Bearer realm="example"
```