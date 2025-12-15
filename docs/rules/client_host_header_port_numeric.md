<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client Host Header Port Numeric

## Description

If the `Host` request header includes a port (for example, `example.com:8080`), the port MUST be a numeric value in the range 1–65535. This rule flags empty, non-numeric, or out-of-range port values.

IPv6 address literals MUST be bracketed when a port is present (e.g., `[::1]:443`). Unbracketed IPv6 literals are intentionally skipped by this check to avoid false positives; there is a separate rule candidate that enforces bracketed IPv6 when a port is present.

## Specifications

- [RFC 9112 §5.4](https://www.rfc-editor.org/rfc/rfc9112.html#section-5.4): Host header field
- [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html): URI authority component

## Configuration

```toml
[rules.client_host_header_port_numeric]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good
```http
Host: example.com
Host: example.com:80
Host: [::1]:443
```

### ❌ Bad
```http
Host: example.com:abc
Host: example.com:
Host: example.com:0
Host: example.com:65536
Host: [::1]:-1
```