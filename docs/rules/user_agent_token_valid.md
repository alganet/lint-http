<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# User Agent Token Valid

## Description

Validate a `User-Agent` request header against `User-Agent = product *( RWS ( product / comment ) )`. Each product is a `token` with an optional `/`-separated version token; parenthesized comments may nest and may hold a `quoted-pair`, but a comment can only follow a product, so a value that opens with one — or holds nothing else — does not match the grammar. Required whitespace between elements is enforced, and `obs-text` is accepted inside a comment, where `ctext` allows it, and nowhere else. What §10.1.5 asks beyond the grammar — that a product identifier carry no advertising or other nonessential information, and no needlessly fine-grained detail — is a question about intent that the octets cannot answer, and is not checked.

## Specifications

- [RFC 9110 §10.1.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.5): `User-Agent = product *( RWS ( product / comment ) )`, a request context field; `product = token ["/" product-version]` is defined here once and `Server` shares it. The section's further requirements — no advertising or nonessential information in a product identifier, no needlessly fine-grained detail — are about intent and are not decidable from a field value
- [RFC 9110 §5.6.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.5): `comment = "(" *( ctext / quoted-pair / comment ) ")"` — comments nest, and `ctext` admits `obs-text` but not the parentheses or the backslash

## Configuration

```toml
[rules.user_agent_token_valid]
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
