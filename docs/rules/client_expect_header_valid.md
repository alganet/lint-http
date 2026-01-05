<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client Expect Header Syntax Valid

## Description

Checks that the `Expect` request header, when present, follows the syntax defined by the HTTP specification. This rule validates that each list member is a `token` (ABNF token) and that any parameter (on the right-hand side of `=`) is either a token or a `quoted-string`. Quoted-string content is validated and supports quoted-pair escapes (`\"`); unescaped control characters (except HTAB) are rejected. Additionally, the special expectation `100-continue` MUST NOT be accompanied by parameters.

## Specifications

- [RFC 9110 §10.1.1 Expect](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.1)

## Configuration

```toml
[rules.client_expect_header_valid]
enabled = true
severity = "error"
```

## Examples

### ✅ Good

```http
PUT /upload HTTP/1.1
Host: example.com
Content-Length: 123456
Expect: 100-continue

GET /foo HTTP/1.1
Host: example.com
Expect: foo

GET /bar HTTP/1.1
Host: example.com
Expect: a="quoted", b=token
```

### ❌ Bad

```http
GET /bad HTTP/1.1
Host: example.com
Expect:
# Empty element

GET /bad2 HTTP/1.1
Host: example.com
Expect: a/b
# '/' illegal in token

POST /upload HTTP/1.1
Host: example.com
Expect: 100-continue=param
# 100-continue must not have parameters
```
