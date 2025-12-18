<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Status Code Valid Range

## Description

HTTP response status codes MUST be in the range 100 through 599. This rule flags responses with status codes outside this range.

The status-code element is a three-digit integer that attempts to understand and satisfy the request. Standardized status codes are grouped into five classes (Informational, Success, Redirection, Client Error, and Server Error), all within the 100-599 range. Codes outside this range are not valid HTTP.

## Specifications

- [RFC 9110 §6](https://www.rfc-editor.org/rfc/rfc9110.html#section-6): Status Codes

## Configuration

```toml
[rules.server_status_code_valid_range]
enabled = true
severity = "error"
```

## Examples

### ✅ Good Response
```http
HTTP/1.1 200 OK
```

### ❌ Bad Response (Out of range)
```http
HTTP/1.1 600 Invalid Status
```

### ❌ Bad Response (Out of range)
```http
HTTP/1.1 99 Something
```
