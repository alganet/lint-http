<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Origin Matching for CORS Responses

## Description

When a server responds to a cross-origin request the `Access-Control-Allow-Origin`
header must either repeat the request's `Origin` value or use the wildcard `*`.
Furthermore, the wildcard may **not** be used in conjunction with credentials
(`Access-Control-Allow-Credentials: true`).

This rule looks at transactions where the client supplied an `Origin` header
and the server returned an `Access-Control-Allow-Origin` header.  It
validates that the header set is semantically consistent with the request
origin and enforces the credential restriction on `*`.  If the request's
`Origin` value is syntactically invalid the rule also raises a violation.

This check applies to server responses (RuleScope::Server).

## Specifications

- RFC 6454 — The Web Origin Concept — https://datatracker.ietf.org/doc/html/rfc6454
- Fetch CORS / Origin matching rules — https://fetch.spec.whatwg.org/#access-control-allow-origin-response-header
- MDN: Access-Control-Allow-Origin — https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin

## Configuration

```toml
[rules.semantic_origin_matching_for_cors]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good (exact echo)

```http
GET /foo HTTP/1.1
Host: example.com
Origin: https://example.org

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://example.org
```

### ✅ Good (wildcard, no credentials)

```http
GET /foo HTTP/1.1
Host: example.com
Origin: https://example.org

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
```

### ❌ Bad (`*` with credentials)

```http
GET /foo HTTP/1.1
Host: example.com
Origin: https://example.org

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

### ❌ Bad (mismatched origin)

```http
GET /foo HTTP/1.1
Host: example.com
Origin: https://foo.example

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://bar.example
```

### ❌ Bad (multiple header fields or list)

```http
GET /foo HTTP/1.1
Host: example.com
Origin: https://example.org

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://a, https://b
```

```http
GET /foo HTTP/1.1
Host: example.com
Origin: https://example.org

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://a
Access-Control-Allow-Origin: https://b
```
