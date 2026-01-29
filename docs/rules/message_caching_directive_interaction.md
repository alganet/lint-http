<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_caching_directive_interaction

## Description
Detect contradictions or redundant combinations in `Cache-Control` directives that affect caching semantics. Examples include `public` and `private` appearing together (contradictory visibility), `no-store` combined with `public`/`private`, and `no-cache` together with `max-age=0` (redundant).

## Specifications

- [RFC 9111 §3](https://www.rfc-editor.org/rfc/rfc9111.html#section-3) — Cache-Control directives and cache semantics

## Configuration
This rule uses the default rule configuration table. Enable it in your config example like:

```toml
[rules.message_caching_directive_interaction]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Cache-Control: public, max-age=3600
```

### ❌ Bad

```http
Cache-Control: public, private

Cache-Control: no-store, public

Cache-Control: no-cache, max-age=0
```
