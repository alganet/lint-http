<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Cross-Origin Resource Policy Value

## Description

This rule checks the `Cross-Origin-Resource-Policy` response header value and ensures it is one of the allowed tokens: **`same-site`**, **`same-origin`**, or **`cross-origin`**. The header must be a single value and must not contain comma-separated lists or multiple header fields. This header is response-only per the W3C Cross-Origin Resource Policy specification; the rule applies to server responses (RuleScope::Server).

## Specifications

- W3C: Cross-Origin Resource Policy — https://w3c.github.io/webappsec-corp/
- MDN: Cross-Origin-Resource-Policy — https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy

## Configuration

```toml
[rules.message_cross_origin_resource_policy_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Cross-Origin-Resource-Policy: same-site
```

### ✅ Good (case-insensitive, trailing whitespace allowed)

```http
HTTP/1.1 200 OK
Cross-Origin-Resource-Policy: SAME-ORIGIN 
```

### ❌ Bad (unsupported value)

```http
HTTP/1.1 200 OK
Cross-Origin-Resource-Policy: private
```

### ❌ Bad (comma-separated list)

```http
HTTP/1.1 200 OK
Cross-Origin-Resource-Policy: same-origin, cross-origin
```
