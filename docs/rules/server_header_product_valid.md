<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Header Product Valid

## Description

Validate a `Server` response header against `Server = product *( RWS ( product / comment ) )`. Each product is a `token` with an optional `/`-separated version token; parenthesized comments may nest and may hold a `quoted-pair`, but a comment can only follow a product, so a value that opens with one — or holds nothing else — does not match the grammar. Required whitespace between elements is enforced, and `obs-text` is accepted inside a comment, where `ctext` allows it, and nowhere else.

## Specifications

- [RFC 9110 §10.2.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.4): `Server = product *( RWS ( product / comment ) )`; the section defines the field and defers the product syntax itself to Section 10.1.5
- [RFC 9110 §10.1.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.5): `product = token ["/" product-version]` and `product-version = token`, defined once under `User-Agent` and shared by `Server`
- [RFC 9110 §5.6.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.5): `comment = "(" *( ctext / quoted-pair / comment ) ")"` — comments nest, and `ctext` admits `obs-text` but not the parentheses or the backslash

## Configuration

```toml
[rules.server_header_product_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0
```

### ✅ Good the example RFC 9110 prints for the field

```http
HTTP/1.1 200 OK
Server: CERN/3.0 libwww/2.17
```

### ✅ Good a comment following a product

```http
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
```

### ❌ Bad no leading product identifier

```http
HTTP/1.1 200 OK
Server: /1.0
```

### ❌ Bad a comment before the first product

```http
HTTP/1.1 200 OK
Server: (Ubuntu) Apache/2.4.41
```

### ❌ Bad illegal character in the product token

```http
HTTP/1.1 200 OK
Server: Bad@Srv/1.0
```

### ❌ Bad illegal character in the product version

```http
HTTP/1.1 200 OK
Server: Srv/1@0
```

### ❌ Bad unterminated comment

```http
HTTP/1.1 200 OK
Server: Bad (unbalanced comment
```
