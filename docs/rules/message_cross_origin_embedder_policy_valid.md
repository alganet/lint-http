<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Cross-Origin-Embedder-Policy Value

## Description

This rule checks the `Cross-Origin-Embedder-Policy` response header value and ensures it uses one of the secure tokens that enable cross-origin isolation: **`require-corp`** or **`credentialless`**. The header must be a single value and must not contain comma-separated lists or multiple header fields. Note: `unsafe-none` is a valid COEP token per the specification, but it does not enable cross-origin isolation; this rule rejects it intentionally to encourage more secure configurations. The rule applies to server responses (RuleScope::Server).

## Specifications

- [MDN Cross-Origin-Embedder-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy): Cross-Origin-Embedder-Policy
- [HTML](https://html.spec.whatwg.org/multipage/browsers.html): Cross-Origin Embedder Policy (W3C): The Cross-Origin-Embedder-Policy header
- [HTML](https://html.spec.whatwg.org/multipage/browsers.html#cross-origin-embedder-policy): HTML Standard / Fetch (describes behavior and interaction with other cross-origin policies)

## Configuration

```toml
[rules.message_cross_origin_embedder_policy_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good (response)

```http
HTTP/1.1 200 OK
Cross-Origin-Embedder-Policy: require-corp
```

### ✅ Good (case-insensitive, whitespace tolerated)

```http
HTTP/1.1 200 OK
Cross-Origin-Embedder-Policy:  CREDENTIALLESS  
```

### ❌ Bad (valid but insecure value)

```http
HTTP/1.1 200 OK
Cross-Origin-Embedder-Policy: unsafe-none
```

### ❌ Bad (comma-separated list)

```http
HTTP/1.1 200 OK
Cross-Origin-Embedder-Policy: require-corp, credentialless
```

### ❌ Bad (multiple header fields)

```http
HTTP/1.1 200 OK
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Embedder-Policy: unsafe-none
```
