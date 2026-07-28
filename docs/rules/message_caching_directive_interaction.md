<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Caching Directive Interaction

## Description

Detect contradictions in `Cache-Control` directives that affect caching semantics: `public` and `private` together (contradictory visibility), `no-store` with `public`/`private`, differing repeated `max-age`/`s-maxage` values, and empty list elements. `no-cache` together with `max-age=0` is a legal combination and is not flagged.

## Specifications

- [RFC 9111 §5.2.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2): Response directives: public (§5.2.2.9), private (§5.2.2.7), no-store (§5.2.2.5), max-age/s-maxage
- [RFC 9111 §4.2.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.1): Conflicting directives are resolved by the most restrictive; multiple values for a directive → first or stale
- [RFC 9110 §5.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1): List (`#rule`) syntax: a sender MUST NOT generate empty list elements

## Configuration

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

Cache-Control: max-age=60, max-age=30
```
