<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful no-cache revalidation

## Description

The `no-cache` cache-control directive (RFC 9111 §5.2.2.4) permits a cache to store a response, but it **must not** use that stored entry to satisfy a subsequent request without first validating it with the origin server.  In practice, caches are expected to issue a conditional request using a validator (usually an `ETag` or `Last-Modified` value) when they have one; if no validator is available the cache may perform an unconditional request, which still contacts the origin server.

This stateful rule reconstructs a small portion of cache state for the current client+resource by locating the most recent prior response that included `Cache-Control: no-cache` and that the request now presented was allowed to be answered from (§4): the same method, or a `HEAD` against a stored `GET`.  Only GET, HEAD and POST have caching semantics at all, so a response to an `OPTIONS` or a `TRACE` is no stored entry even against a later request of its own method, and a stored `GET` is no candidate for an `OPTIONS`, a `TRACE`, or an unsafe method — where nothing could have been reused there is no reuse to report.  If that response also carried a validator and the current request is unconditional (no `If-None-Match` or `If-Modified-Since` headers), the rule emits a warning.  The presence of validators is required to avoid false alarms in cases where the entry could not possibly be revalidated.

The check deliberately ignores request-side `Cache-Control: no-cache` clauses and makes no attempt to calculate freshness; it simply tracks whether a conditional header was omitted.  Only the unqualified directive is enforced: a qualified `no-cache="field"` response may be reused (revalidating only the named fields) and is not flagged.  **What this rule does not observe is the reuse itself.** §5.2.2.4 bars using a stored `no-cache` response *without forwarding it for validation*, and this implementation reads the seam between a client and an origin — a cache that had answered from its stored entry would have put nothing on that seam. Every request reaching this rule is one the cache declined to answer, so the forwarding the directive requires has happened, and §4.3 says a cache *can* use the conditional mechanism rather than that it must. The finding is therefore the narrower one the wire supports: a validator was held and not sent, costing a body where a `304` would have done. That is why it is a `warn` whose obligation is recorded as unstated — the `MUST NOT` is addressed to the cache, not to the client the finding names. This rule complements `max_age_directive_valid` and `must_revalidate_enforced` by focussing on the specific behaviour mandated by the `no-cache` directive.

## Violations

- [cache_control_no_cache_ignored](../violations/cache_control_no_cache_ignored.md) — A no-cache response is re-requested without its validator

## Specifications

- [RFC 9111 §5.2.2.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.4): no-cache — the unqualified form's prohibition on reuse without forwarding for validation, the argument syntax `#field-name`, the qualified form defined as an argument listing one or more field names, and the Note that caches often handle it as an unqualified no-cache
- [RFC 9111 §4.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3): Validation (the conditional request that satisfies no-cache)
- [RFC 9110 §9.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.3): Methods and Caching (which methods leave a stored response behind at all)
- [RFC 9111 §4](https://www.rfc-editor.org/rfc/rfc9111.html#section-4): Constructing Responses from Caches (which stored response may answer a presented request)

## Configuration

```toml
[rules.no_cache_revalidation]
enabled = true
```

## Examples

### ✅ Good — conditional request satisfies no-cache requirement

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: no-cache
< ETag: "v1"

# later:
> GET /resource HTTP/1.1
> Host: example.com
> If-None-Match: "v1"    # conditional request used; no violation
```

### ✅ Good — no validator means unconditional request is acceptable

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: no-cache

# client cannot compose a conditional request; unconditional fetch is fine
> GET /resource HTTP/1.1
> Host: example.com
```

### ✅ Good — a method the stored entry could not have answered

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: no-cache
< ETag: "v1"

# later, a different method on the same resource:
> OPTIONS /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 405 Method Not Allowed

# no cache answers an OPTIONS from a stored GET, so nothing was reused
```

### ❌ Bad — reused entry without revalidation

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: no-cache
< ETag: "v1"

# later, client repeats request but omits validator
> GET /resource HTTP/1.1
> Host: example.com
# violation: cached response required conditional revalidation
```
