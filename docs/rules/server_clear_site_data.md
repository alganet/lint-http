<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Clear Site Data

## Description

Checks that configured logout paths include a `Clear-Site-Data` header so client-side storage (cookies, cache, storage) is cleared on logout.

## Specifications

- [W3C Clear Site Data Specification](https://www.w3.org/TR/clear-site-data/)
- [MDN: Clear-Site-Data](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data)

## Configuration

```toml
[rules.server_clear_site_data]
enabled = true
severity = "warn"
paths = ["/logout", "/signout", "/auth/logout", "/api/logout"]
```

## Examples

### ✅ Good Response

```http
POST /logout HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: application/json
Clear-Site-Data: "*"
```

### ❌ Bad Response

```http
POST /logout HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: application/json
# Missing Clear-Site-Data
```
