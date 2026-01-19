<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_user_agent_token_valid

## Description

`User-Agent` header values SHOULD be syntactically valid `product` tokens as defined by HTTP (token ["/" token]) and MAY include parenthesized comments. This rule validates product tokens and their optional version tokens, and flags invalid characters, empty tokens, or malformed comments.

## Specifications

- [RFC 9110 §10.1.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.5) — `User-Agent` header field and `product` syntax (token ["/" product-version])

## Configuration

```toml
[rules.message_user_agent_token_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET / HTTP/1.1
Host: example.org
User-Agent: curl/7.68.0
```

```http
GET / HTTP/1.1
Host: example.org
User-Agent: Mozilla/5.0 (compatible; Bot/1.0; +http://example.com)
```

### ❌ Bad

```http
GET / HTTP/1.1
Host: example.org
User-Agent: Bad UA!
```

```http
GET / HTTP/1.1
Host: example.org
User-Agent: /1.0
```
