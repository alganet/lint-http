<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Cache Control And Pragma Consistent

## Description

Reports the deprecated `Pragma` field wherever it appears, and one contradiction it takes part in.

**The deprecation is not direction-specific.** RFC 9111 § 5.4 opens by naming the `Pragma` *request* header field and closes with "this specification deprecates Pragma"; the field registry in § 11 records its status as `deprecated` with no direction attached. So a request carrying one is reported, which is the deprecated thing being done, and a response carrying one is reported too — there the field was never given a meaning at all, which § 5.4's Note states when it says `Pragma: no-cache` cannot stand in for `Cache-Control: no-cache` in a response. One entry, one retired field, and the message names which side wrote it.

**The contradiction is a heuristic and says so.** `Pragma: no-cache` asks a cache to validate with the origin and `Cache-Control: only-if-cached` asks it to answer from what it holds or fail, so a request carrying both asks for opposite things. No sentence forbids the combination.

What a `Pragma` value may contain is `pragma_token_valid`'s question, not this rule's.

## Violations

- [pragma_conflicting](../violations/pragma_conflicting.md) — A request asks for no-cache and only-if-cached at once
- [pragma_obsolete](../violations/pragma_obsolete.md) — A message carries a field this specification deprecates

## Specifications

- [RFC 9111 §5.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.4): Pragma — defined for HTTP/1.0 caches so a client could ask for `no-cache`, superseded by `Cache-Control`, deprecated by this specification, and never given a meaning in a response at all

## Configuration

```toml
[rules.cache_control_and_pragma_consistent]
enabled = true
```

## Examples

### ✅ Good

```http
GET /resource HTTP/1.1
Host: example.com
Cache-Control: no-cache, max-age=0

HTTP/1.1 200 OK
Cache-Control: no-cache
```

### ❌ Bad — a request carries the deprecated field

```http
GET /resource HTTP/1.1
Host: example.com
Pragma: no-cache

# The direction § 5.4 defines, and the one it deprecates
```

### ❌ Bad — and the two directives ask for opposite things

```http
GET /resource HTTP/1.1
Host: example.com
Pragma: no-cache
Cache-Control: only-if-cached

# Contradictory directives: 'no-cache' requests should not force 'only-if-cached'
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Pragma: no-cache

# 'Pragma' in responses has unspecified semantics; use 'Cache-Control' instead
```

```http
HTTP/1.1 200 OK
Pragma: foo

# Any Pragma in responses is discouraged; prefer Cache-Control
```
