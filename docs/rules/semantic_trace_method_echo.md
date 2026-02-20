<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Semantic TRACE Method Echo

## Description

Validate TRACE method semantics with two pragmatic checks:
1. A TRACE request must not carry content.
2. If a TRACE response carries content, it should use `Content-Type: message/http`.

These checks help catch incorrect TRACE handling and improve interoperability for diagnostics tooling.

## Specifications

- [RFC 9110 §9.3.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.8): TRACE semantics; clients `MUST NOT` send content in TRACE requests, and successful TRACE responses `SHOULD` use `message/http`.
- [RFC 9110 §8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3): `Content-Type` field semantics.

## Configuration

```toml
[rules.semantic_trace_method_echo]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
TRACE /diagnostics HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: message/http
Content-Length: 29

TRACE /diagnostics HTTP/1.1
```

### ❌ Bad

```http
TRACE /diagnostics HTTP/1.1
Host: example.com
Content-Length: 4

ping
```

```http
TRACE /diagnostics HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 29

TRACE /diagnostics HTTP/1.1
```
