<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client Request Method Body Consistency

## Description

Validate request methods for unexpected message bodies. Some request methods (notably `GET` and `HEAD`) have no defined request payload semantics; sending a non-empty message body with such methods may lead to undefined or rejected behavior by intermediaries and servers.

This rule flags client requests using `GET` or `HEAD` that appear to include a message body. Presence of a `Transfer-Encoding` header or a non-zero `Content-Length` header indicates a message body and will be flagged. A zero `Content-Length: 0` is tolerated.

## Specifications

- [RFC 9110 §6.3 — Request Methods: GET and HEAD do not define request payload semantics; servers and intermediaries may ignore or reject request bodies for these methods.](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.3)

## Configuration

```toml
[rules.client_request_method_body_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /resource HTTP/1.1
Host: example.com
```

```http
GET /resource HTTP/1.1
Host: example.com
Content-Length: 0
```

### ❌ Bad

```http
GET /resource HTTP/1.1
Host: example.com
Content-Length: 10
```

```http
HEAD /resource HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
```
