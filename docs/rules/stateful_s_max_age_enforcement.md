<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful s-maxage Enforcement

## Description

Responses that include a `Cache-Control: s-maxage=<seconds>` directive are
intended to limit how long **shared** caches may consider the representation
fresh.  Private caches (e.g. in a browser or single-client proxy) **must
ignore** `s-maxage` and instead rely on the ordinary freshness lifetime
(`max-age`, `Expires`, heuristics, etc.).  Misinterpreting `s-maxage` on the
client side can lead to unnecessary conditional requests and wasted network
traffic.

This rule watches a series of transactions from the same client and examines
the most recent prior response for the same resource that carried both an
`<s-maxage>` value and a larger `max-age`.  If the client subsequently issues
a conditional request **after** the `s-maxage` interval but **before** the
`max-age` interval has elapsed, the cached entry was still fresh according to
the private-cache semantics and revalidation was premature.  A warning is
issued in that case.

## Specifications

- [RFC 9111 §5.2 — `s-maxage` directive](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2) — applies only to shared caches and overrides `max-age`/`Expires` for those caches.

## Configuration

```toml
[rules.stateful_s_max_age_enforcement]
enabled = true
severity = "warn"
```

## Examples

### ❌ Bad — premature revalidation based on `s-maxage`

```
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=3600, s-maxage=60
< ETag: "v1"

# seconds later, same client revalidates after 120s (s-maxage expired but
# max-age still valid)
> GET /resource HTTP/1.1
> Host: example.com
> If-None-Match: "v1"
```

This triggers the rule: private cache should not have treated the entry as
stale at 120 s because the `max-age` lifetime of 3600 s remained in effect.

### ✅ Good behaviours

- Conditional requests sent **after** `max-age` has expired.
- Unconditional requests between `s-maxage` and `max-age` (private cache may
  freely reuse fresh entries).
- Requests from a different client: shared caches are allowed to revalidate
  once `s-maxage` expires, and the rule only examines history per client.
