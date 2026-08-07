<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message User Agent Token Valid

## Description

`User-Agent` header values SHOULD be syntactically valid `product` tokens as defined by HTTP (token ["/" token]) and MAY include parenthesized comments. This rule validates product tokens and their optional version tokens, and flags invalid characters, empty tokens, or malformed comments.

## Specifications

- [RFC 9110 §10.1.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.5): `User-Agent` header field and `product` syntax (token ["/" product-version])

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

### ✅ Good the example RFC 9110 prints for the field

```http
GET / HTTP/1.1
Host: example.org
User-Agent: CERN-LineMode/2.15 libwww/2.17b3
```

### ✅ Good comments following a product

```http
GET / HTTP/1.1
Host: example.org
User-Agent: Mozilla/5.0 (compatible; Bot/1.0; +http://example.com)
```

### ❌ Bad no leading product identifier

```http
GET / HTTP/1.1
Host: example.org
User-Agent: /1.0
```

### ❌ Bad a comment before the first product

```http
GET / HTTP/1.1
Host: example.org
User-Agent: (compatible; Bot/1.0) Mozilla/5.0
```

### ❌ Bad illegal character in the product token

```http
GET / HTTP/1.1
Host: example.org
User-Agent: Bad@UA/1.0
```

### ❌ Bad no whitespace between the product and the comment

```http
GET / HTTP/1.1
Host: example.org
User-Agent: Mozilla/5.0(Windows)
```

### ❌ Bad unterminated comment

```http
GET / HTTP/1.1
Host: example.org
User-Agent: Mozilla/5.0 (unbalanced comment
```
