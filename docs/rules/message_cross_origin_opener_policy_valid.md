<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Cross-Origin-Opener-Policy Value

## Description

This rule checks the `Cross-Origin-Opener-Policy` response header value and ensures it is one of the allowed tokens: **`same-origin`**, **`same-origin-allow-popups`**, or **`unsafe-none`**. The header must be a single value and must not contain comma-separated lists or multiple header fields. This header is response-only per the HTML and W3C Cross-Origin-Opener-Policy specifications; the rule applies to server responses (RuleScope::Server).

## Specifications

- MDN: Cross-Origin-Opener-Policy — https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy
- Cross-Origin-Opener-Policy (W3C): “The Cross-Origin-Opener-Policy header” — https://www.w3.org/TR/cross-origin-opener-policy/#the-cross-origin-opener-policy-header
- HTML Standard: “Cross-origin opener policies” (defines header behavior and allowed values) — https://html.spec.whatwg.org/multipage/browsers.html#cross-origin-opener-policies

## Configuration

```toml
[rules.message_cross_origin_opener_policy_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good (response)

```http
HTTP/1.1 200 OK
Cross-Origin-Opener-Policy: same-origin
```

### ✅ Good (case-insensitive, whitespace tolerated)

```http
HTTP/1.1 200 OK
Cross-Origin-Opener-Policy:  SAME-ORIGIN-ALLOW-POPUPS  
```

### ❌ Bad (unsupported value)

```http
HTTP/1.1 200 OK
Cross-Origin-Opener-Policy: other
```

### ❌ Bad (comma-separated list)

```http
HTTP/1.1 200 OK
Cross-Origin-Opener-Policy: same-origin, unsafe-none
```

### ❌ Bad (multiple header fields)

```http
HTTP/1.1 200 OK
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Opener-Policy: unsafe-none
```
