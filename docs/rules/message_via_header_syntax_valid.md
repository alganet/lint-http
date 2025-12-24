<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Via Header Syntax Valid

## Description

Validates `Via` header field-values follow the list of received-protocol and received-by entries as specified by RFC 9110 §7.6.3. Each entry should include a protocol token (e.g., `1.1` or `HTTP/1.1`) and a `received-by` token (host, pseudonym, or IP with optional port); comments are allowed in parentheses.

## Specifications

- [RFC 9110 §7.6.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.3): Via header

## Configuration

```toml
[rules.message_via_header_syntax_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Via: 1.1 example.com
Via: HTTP/1.1 example.com, 1.0 proxy.example.com:8080
Via: 1.1 example.com (cached)
```

### ❌ Bad

```http
Via: 1.1
# missing received-by

Via: HT@P/1.1 proxy.example.com
# invalid protocol token

Via: 1.1 example.com:port
# non-numeric port

Via: 1.1 example.com, , 1.0 proxy
# empty element
```
