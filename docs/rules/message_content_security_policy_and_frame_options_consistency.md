<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_content_security_policy_and_frame_options_consistency

## Description

Detect contradictory framing directives between `Content-Security-Policy` (the `frame-ancestors` directive) and `X-Frame-Options`. These headers express framing restrictions; when they conflict, they create ambiguity that may cause different user agents to allow or block framing inconsistently.

Note: this check considers only enforceable header-delivered CSP policies (`Content-Security-Policy`); `Content-Security-Policy-Report-Only` is ignored because it does not itself change framing enforcement.

## Specifications

- [Content Security Policy (CSP) — `frame-ancestors` directive (W3C CSP spec §6.4.2)](https://www.w3.org/TR/CSP3/#directive-frame-ancestors). Note: when present and enforceable, `frame-ancestors` overrides `X-Frame-Options` (see §6.4.2.2).
- [HTML Living Standard — `X-Frame-Options` header and its relation to `frame-ancestors`](https://html.spec.whatwg.org/multipage/speculative-loading.html#the-x-frame-options-header).
- [MDN — `X-Frame-Options`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options) — legacy header with values `DENY`, `SAMEORIGIN`, and the obsolete `ALLOW-FROM`. Note: `ALLOW-FROM` is deprecated and not supported by most modern browsers — prefer using CSP's `frame-ancestors` for origin-specific framing policies.

## Configuration

```toml
[rules.message_content_security_policy_and_frame_options_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Content-Security-Policy: frame-ancestors 'none'
# No X-Frame-Options header present
```

### ✅ Good

```http
Content-Security-Policy: frame-ancestors https://example.com
X-Frame-Options: ALLOW-FROM https://example.com
```

### ❌ Bad

```http
Content-Security-Policy: frame-ancestors 'none'
X-Frame-Options: SAMEORIGIN
# CSP disallows all framing but XFO says allow same origin -> contradiction
```

### ❌ Bad

```http
Content-Security-Policy: frame-ancestors 'self'
X-Frame-Options: DENY
# CSP allows same-origin framing while XFO denies all framing -> contradiction
```