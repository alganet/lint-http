<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_server_header_product_valid

## Description

Validate the `Server` response header's product tokens and optional product versions. Each product must be a `token` and the optional version (after `/`) must also be a `token`. Parenthesized comments are accepted per the header's grammar and are ignored for token validation.

## Specifications

- [RFC 9110 §7.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1.1) — `Server` header field and `product` grammar: product = token ["/" product-version] *( RWS ( product / comment ) )

## Configuration

Enable the rule in the TOML configuration (rules are disabled by default):

```toml
[rules.message_server_header_product_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0

HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Server: /1.0  # empty product token

HTTP/1.1 200 OK
Server: Bad@Srv/1.0  # illegal character in product

HTTP/1.1 200 OK
Server: Srv/1@0  # illegal character in version

HTTP/1.1 200 OK
Server: Bad (unbalanced comment  # unterminated comment
```
