<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client Request Method Token Valid

## Description

HTTP request methods are tokens and must conform to the `token` (tchar) grammar. This rule flags method tokens that contain invalid characters (for example, spaces, control characters, `@`) or include lowercase alphabetic characters.

## Specifications

- [RFC 9112 §5.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-5.1): Methods
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens (tchar)

## Configuration

```toml
[rules.client_request_method_token_valid]
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