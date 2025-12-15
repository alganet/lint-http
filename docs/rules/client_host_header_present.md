<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client Host Header Present

## Description

This rule checks that HTTP requests include a `Host` header when required by the HTTP specification. A `Host` header is mandatory for HTTP/1.1 origin-form requests and is used by servers to determine the target host.

## Specifications

- [RFC 9112 §3.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2): Host header field in requests

## Configuration

```toml
[rules.client_host_header_present]
enabled = true
severity = "info"
```

## Examples

### ✅ Good Request
```http
GET /path HTTP/1.1
Host: example.com
```

### ❌ Bad Request
```http
GET /path HTTP/1.1
# Missing Host header
```

