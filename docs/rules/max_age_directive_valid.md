<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful max-age directive validity

## Description

Responses tagged with a `Cache-Control` `max-age=<seconds>` directive promise that the representation may safely be reused without revalidation for `<seconds>` seconds after it was stored.

This rule reconstructs a very small piece of cache state for a given client+resource by examining the most recent prior response that included a parseable `max-age` directive.  It then computes an approximate "age" for that stored response using any `Age` header it carried plus the time elapsed since it was observed.

One thing is reported: sending a **conditional request** (`If-None-Match` or `If-Modified-Since`) while the cached copy is still fresh (age < max‑age).  Revalidation at this point is a redundant round‑trip — a fresh response can be reused without contacting the origin at all.

**Unless the request refused the stored response itself.** A request carrying `no-cache` (or `Pragma: no-cache` with no `Cache-Control`), a `max-age` the entry has outlived, or a `min-fresh` it cannot meet has told the cache not to reuse the entry unvalidated (RFC 9111 §5.2.1). That is what a browser sends on a reload, and it is not reported: the round-trip is the one the client asked for.

It is an efficiency finding rather than a protocol violation: RFC 9111 §4.2 frames fresh reuse as something a cache *can* do, not an obligation, so the entry names no sentence.  The exception is `Cache-Control: immutable`, which does turn early revalidation into a SHOULD NOT; that is [a separate rule](immutable_cache_never_stale.md).

**The other side of the comparison is not reported here.** A stale entry refetched without a conditional request is [`cached_validators_reused`](cached_validators_reused.md)'s finding, from the same evidence: that rule asks for a validator on the stored response and no precondition on this request, without consulting freshness at all, so it makes every report this rule could make and does not need the freshness estimate to make it.

## Violations

- [conditional_redundant](../violations/conditional_redundant.md) — A still-fresh stored response is revalidated anyway

## Specifications

- [RFC 9111 §4.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2): Freshness — fresh/stale definitions, and reuse without contacting the origin as an efficiency opportunity (age itself is calculated per §4.2.3)

## Configuration

```toml
[rules.max_age_directive_valid]
enabled = true
```

## Examples

### ✅ Good — fresh entry reused without conditional headers

```http
> GET /data HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=60

# thirty seconds later, no request is even sent (cache hit), so linter
# never observes a transaction.  If a request were visible, it would not
# include conditional headers during the freshness window.
```

### ✅ Good — stale entry revalidated

```http
> GET /data HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=1
< ETag: "v1"

# later, after expiry:
> GET /data HTTP/1.1
> Host: example.com
> If-None-Match: "v1"    # conditional request used
```

### ✅ Good — a method the stored entry could not have answered

```http
> OPTIONS /data HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=600

# later, a GET for the same resource, carrying a validator from an entry
# this linter never saw:
> GET /data HTTP/1.1
> Host: example.com
> If-None-Match: "v1"

# no cache stores an OPTIONS response, so its max-age describes no entry and
# this GET revalidated nothing early
```

### ✅ Good — a validator for a variant this request did not select

```http
> GET /style.css HTTP/1.1
> Host: example.com
> Accept-Encoding: gzip

< HTTP/1.1 200 OK
< Cache-Control: max-age=600
< Vary: Accept-Encoding
< ETag: "v1"

# later, the same resource asked for without a coding preference:
> GET /style.css HTTP/1.1
> Host: example.com
> If-None-Match: "v1"

# the fresh entry is the gzip variant, which could not have answered this
# request, so the round trip was not spent confirming a copy it could use
```

### ✅ Good — a reload, which refuses the stored response itself

```http
> GET /data HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=60
< Age: 5
< ETag: "v1"

# the user reloads: the browser asks for a response no older than 0s
> GET /data HTTP/1.1
> Host: example.com
> Cache-Control: max-age=0
> If-None-Match: "v1"

# the stored response is older than the request accepts, so validating it is
# what the client asked for
```

### ❌ Bad — unnecessary revalidation while still fresh

```http
> GET /data HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=60
< ETag: "v1"

# ten seconds later, client inexplicably revalidates
> GET /data HTTP/1.1
> Host: example.com
> If-None-Match: "v1"    # age 10 < 60, should not revalidate yet
```
