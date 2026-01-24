<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Content Security Policy Validity

## Description

Validate basic `Content-Security-Policy` syntax in responses. This rule checks that the header value is UTF-8, not empty, directives are present and well-formed (directive names follow `token` grammar), and common structural issues are flagged (unterminated single-quoted keywords, empty directives due to trailing semicolons, empty nonces/hashes).

This rule is intentionally conservative: it is not a full CSP grammar validator, but catches common, obvious mistakes and misconfigurations.

## Specifications

- W3C Content Security Policy Level 3 — directive and source-list syntax: https://www.w3.org/TR/CSP3/
- Mozilla MDN overview and directive examples: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy

## Configuration

```toml
[rules.server_content_security_policy_validity]
# enabled = true
# severity = "warn" # info|warn|error
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Content-Security-Policy: default-src 'self'; script-src 'nonce-abc123' https://example.com; upgrade-insecure-requests
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Content-Security-Policy: 
```

```http
HTTP/1.1 200 OK
Content-Security-Policy: def@ult-src 'self'
```

```http
HTTP/1.1 200 OK
Content-Security-Policy: default-src 'self'; 
```

```http
HTTP/1.1 200 OK
Content-Security-Policy: default-src 'self
```
