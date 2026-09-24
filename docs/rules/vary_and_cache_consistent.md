<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Vary and Cache Consistency

## Description

When a response includes `Vary: *`, no cache reuses it without validation: a `Vary: *` always fails to match (RFC 9111 §4.1), so the only reuse left is the kind a request forwarded to the origin can establish — RFC 9110 §12.5.5: a recipient "will not be able to determine whether this response is appropriate for a later request without forwarding the request to the origin server". A freshness lifetime is a licence for the other kind — `Cache-Control: max-age` and `s-maxage` say how long a stored response may be served *without* asking — so on such a response it is never used. This rule flags each freshness directive written beside `Vary: *`.

**`public` is not flagged.** It licenses a cache to store the response, and a stored `Vary: *` response is still one a cache may validate and then serve: RFC 9111 §4.3.1 lets a cache validate a response it cannot choose with the request it is sending. `no-cache` is not flagged either: it asks for validation, which is what the wildcard already makes every reuse need.

**Two reasonable readings, one finding.** An operator writing `max-age=86400` beside `Vary: *` either wanted a cache and has none that serves without asking, or wanted none and wrote a lifetime nothing will read; either way one of the two fields is not doing what it says.

## Violations

- [cache_control_redundant](../violations/cache_control_redundant.md) — A freshness lifetime sits on a response never reused without validation

## Specifications

- [RFC 9111 §4.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1): Calculating Cache Keys with the Vary Header Field — a `Vary: *` never matches, so a stored response of that resource is never reused without validation and a freshness lifetime on it has nothing to act on
- [RFC 9111 §3](https://www.rfc-editor.org/rfc/rfc9111.html#section-3): Storing Responses in Caches (cacheability requirements)

## Configuration

```toml
[rules.vary_and_cache_consistent]
enabled = true
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Vary: Accept-Encoding
Cache-Control: max-age=3600

<response body>
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Vary: *
Cache-Control: max-age=3600

<response body>
```
