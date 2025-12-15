<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client Host Header Syntax

## Description

This rule validates the `Host` request header for common syntax mistakes:

- If the header includes a port (for example, `example.com:8080`), the port MUST be a numeric value in the range 1–65535.
- If an IPv6 address literal is used together with a port, the IPv6 literal MUST be enclosed in square brackets (for example, `[::1]:443`).
- The `Host` header MUST NOT include userinfo (for example, `user:pass@host`).

The rule flags empty, non-numeric, or out-of-range ports, and unbracketed IPv6 literals that include a port.

## Specifications

- [RFC 9112 §5.4](https://www.rfc-editor.org/rfc/rfc9112.html#section-5.4): Host header field
- [RFC 3986 §3.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2): Authority component and IP-literals

## Configuration

```toml
[rules.client_host_header_syntax]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Host: example.com
Host: example.com:80
Host: [::1]:443
Host: fe80::1
```

### ❌ Bad

```http
Host: example.com:abc
Host: example.com:
Host: example.com:0
Host: example.com:65536
Host: fe80::1:80
Host: fe80::abcd:8080
Host: user:pass@example.com
Host: user@example.com:80
Host: user:pass@[::1]:80
```
