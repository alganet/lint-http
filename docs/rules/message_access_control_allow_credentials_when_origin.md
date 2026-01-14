<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Access-Control Allow Credentials When Origin

## Description

This rule checks Cross-Origin Resource Sharing (CORS) response headers to ensure that `Access-Control-Allow-Credentials` is **not** set to `true` when `Access-Control-Allow-Origin` is `*` (wildcard). Allowing credentials with a wildcard origin is insecure and disallowed by the CORS model.

## Specifications

- MDN: Access-Control-Allow-Credentials — https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials
- MDN: Access-Control-Allow-Origin — https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
- Fetch Standard: Access-Control-Allow-Credentials — https://fetch.spec.whatwg.org/#http-access-control-allow-credentials

## Configuration

```toml
[rules.message_access_control_allow_credentials_when_origin]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Credentials: true
```

### ✅ Good (no credentials)

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
```

### ❌ Bad (wildcard with credentials)

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
