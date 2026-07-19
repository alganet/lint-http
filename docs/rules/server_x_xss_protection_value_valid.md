<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server X-XSS-Protection Value Valid

## Description

This rule checks that the `X-XSS-Protection` response header, when present, uses an expected and safe value. Historically, the header accepted `0` to disable the browser's cross-site scripting filter and `1; mode=block` to enable blocking; other values are unsupported or ambiguous and should be avoided.

## Specifications

- [MDN X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-XSS-Protection): X-XSS-Protection
- [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/): OWASP guidance

## Configuration

```toml
[rules.server_x_xss_protection_value_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
X-XSS-Protection: 0
```

```http
HTTP/1.1 200 OK
X-XSS-Protection: 1; mode=block
```

### ❌ Bad

```http
HTTP/1.1 200 OK
X-XSS-Protection: 1
```

```http
HTTP/1.1 200 OK
X-XSS-Protection: 2
```

```http
HTTP/1.1 200 OK
X-XSS-Protection: 1; report=1
```
