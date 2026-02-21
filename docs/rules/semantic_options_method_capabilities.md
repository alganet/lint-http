<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# semantic_options_method_capabilities

## Description

When a server responds to an `OPTIONS` request with a successful status code, it
is expected to advertise the set of communication options supported for the
selected resource.  An `Allow` header field is the canonical way to list the
methods that are allowed, and absence of the header hinders clients and
intermediaries from discovering what operations are permitted.

This rule flags successful `OPTIONS` responses that omit the `Allow` header.

## Specifications

- [RFC 9110 §9.3.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.7):
  OPTIONS method semantics ("A server generating a successful response to
  OPTIONS SHOULD send any header that might indicate optional features
  implemented by the server and applicable to the target resource (e.g.,
  Allow)").
- [RFC 9110 §10.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.1):
  `Allow` header field definition.

## Configuration

```toml
[rules.semantic_options_method_capabilities]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
OPTIONS /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Allow: GET, POST, OPTIONS
```

```http
OPTIONS /resource HTTP/1.1
Host: example.com

HTTP/1.1 204 No Content
Allow: OPTIONS
```

### ❌ Bad

```http
OPTIONS /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/plain
# missing Allow header
```