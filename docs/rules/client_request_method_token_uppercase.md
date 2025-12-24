<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client Request Method Token Uppercase

## Description

HTTP request methods are case-sensitive tokens. This rule ensures method tokens are composed of valid token characters and that alphabetic characters are uppercase (for example, `GET`, `POST`). Lowercase or mixed-case method tokens are flagged.

## Specifications

- [RFC 9110 §9.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1): Methods
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens

## Configuration

```toml
[rules.client_request_method_token_uppercase]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /index.html HTTP/1.1
```

### ❌ Bad

```http
get /index.html HTTP/1.1
```