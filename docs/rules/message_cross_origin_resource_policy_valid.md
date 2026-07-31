<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Cross-Origin Resource Policy Value

## Description

This rule checks the `Cross-Origin-Resource-Policy` response header value and ensures it is one of the allowed tokens: **`same-site`**, **`same-origin`**, or **`cross-origin`**. The comparison is **case-sensitive**, as the Fetch Standard's ABNF requires: a user agent that does not recognize the value sets the policy to null and serves the resource as though the header were never sent, so a miscased `SAME-ORIGIN` is not a weaker protection but no protection at all. Surrounding whitespace is still tolerated. The header must be a single value and must not contain comma-separated lists or multiple header fields. This header is response-only; the rule applies to server responses (RuleScope::Server).

## Specifications

- [Fetch §3.7](https://fetch.spec.whatwg.org/#cross-origin-resource-policy-header): `Cross-Origin-Resource-Policy` — the case-sensitive `same-origin`/`same-site`/`cross-origin` grammar, and unrecognized values set to null
- [MDN Cross-Origin-Resource-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Resource-Policy): Cross-Origin-Resource-Policy

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

### ✅ Good (trailing whitespace tolerated)

```http
HTTP/1.1 200 OK
Cross-Origin-Resource-Policy: same-origin 
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
