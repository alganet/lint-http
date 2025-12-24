<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Connection Header Tokens Valid

## Description

Ensures tokens in the `Connection` header are syntactically valid header field-name tokens.

The `Connection` header nominates header field names that are hop-by-hop for the connection. Each token in a `Connection` field must be a valid token that can appear as a header field name (i.e., match the tchar grammar). Rejecting malformed tokens helps catch header-injection or malformed requests.

For each `Connection` header field and each comma-separated token:
- The token must be non-empty.
- The token must match header field-name syntax (as parsed by `hyper::header::HeaderName`).

The rule treats token syntax only; it does not currently require that the named header field actually be present in the message (some tokens are connection options, e.g., `close`).

## Specifications

- [RFC 9110 §7.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1): Connection header field

## Configuration

```toml
[rules.message_connection_header_tokens_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Connection: upgrade, keep-alive
```

### ❌ Bad

```http
Connection: a/b
# "/" not allowed in header name

Connection: ""
# empty token
```
