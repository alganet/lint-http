<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Caching Directive Interaction

## Description

Detect contradictions in `Cache-Control` directives that affect caching semantics: `public` and `private` together (contradictory visibility), `no-store` with `public`/`private`, differing repeated `max-age`/`s-maxage` values, and empty list elements. `no-cache` together with `max-age=0` is a legal combination and is not flagged.

## Specifications

- [RFC 9111 §5.2.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2): Response directives: public (§5.2.2.9), private (§5.2.2.7), no-store (§5.2.2.5), max-age/s-maxage
- [RFC 9111 §5.2.2.5](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.5): `no-store` — a cache MUST NOT store any part of the request or the response, and MUST NOT use the response to satisfy another request
- [RFC 9111 §5.2.2.7](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.7): private — the unqualified form's prohibition on a shared cache storing the response at all, the argument syntax `#field-name`, the qualified form defined as an argument listing one or more field names, and the Note that caches often handle it as an unqualified private
- [RFC 9111 §5.2.2.9](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.9): `public` — a cache MAY store the response even where it would otherwise be prohibited
- [RFC 9111 §4.2.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.1): Calculating Freshness Lifetime — the order a cache consults `s-maxage`, `max-age` and `Expires` in, and what it may do when one directive is present more than once
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The list construct — `1#element => element *( OWS "," OWS element )`, and the sender's MUST NOT against an empty element

## Configuration

```toml
[rules.caching_directive_interaction]
enabled = true
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
