<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# A CORS grant chosen from the Origin is keyed on it

## Description

Reports a cacheable response without `Origin` in its `Vary`, for a resource whose `Access-Control-Allow-Origin` has been seen to change with the request's `Origin`.

**Fetch describes the failure step by step** in its background note on CORS and HTTP caches. A server that sends `Access-Control-Allow-Origin` only in answer to a CORS request sends a response without it to a navigation; the browser caches that, and answers the next CORS request for the resource from the cache, without the header, so the request fails. A server that echoes the `Origin` it was sent has the same problem between two origins: a cache hands the second origin the first one's grant. *"If CORS protocol requirements are more complicated than setting `Access-Control-Allow-Origin` to * or a static origin, `Vary` is to be used."*

**The evidence is two responses, never one.** A value equal to the request's `Origin` is also what a static single-origin configuration sends whenever that origin is the one asking, and Fetch says a static origin needs no `Vary`. What shows the value is computed is two responses for the resource that answer requests with different `Origin` values (one of them may send no `Origin`) and carry different `Access-Control-Allow-Origin` values (one of them may send none). Both must be `GET` answers of the same status that a cache could have stored (RFC 9111 §3), from the same client for the same target URI: a `404` without CORS headers beside a `200` with them is two states of the resource rather than a selection.

**Every response of such a resource owes it**, the non-CORS ones included: the cached response Fetch's example goes wrong with is the one to a navigation. `Vary: *` satisfies it.

**Not this rule's.** Whether `Access-Control-Allow-Origin` is well formed, or agrees with `Access-Control-Allow-Credentials`, belongs to the CORS header rules; a preflight (`OPTIONS`) response is not cached by HTTP caches at all.

## Violations

- [vary_origin_missing](../violations/vary_origin_missing.md) — An Access-Control-Allow-Origin chosen from the Origin is not keyed on it

## Specifications

- [Fetch](https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches): CORS protocol and HTTP caches (informative) — where Access-Control-Allow-Origin depends on the request's Origin, Vary is to be used, or a cached non-CORS response is handed to a later CORS request

## Configuration

```toml
[rules.vary_and_cors_consistent]
enabled = true
```

## Examples

### ✅ Good — the grant follows the Origin, and Vary says so

```http
GET /data HTTP/1.1
Host: api.example.com

HTTP/1.1 200 OK
Vary: Origin
Cache-Control: max-age=600

GET /data HTTP/1.1
Host: api.example.com
Origin: https://app.example.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://app.example.com
Vary: Origin
Cache-Control: max-age=600
```

### ✅ Good — a static grant, sent to every request

```http
GET /data HTTP/1.1
Host: api.example.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Cache-Control: max-age=600

GET /data HTTP/1.1
Host: api.example.com
Origin: https://app.example.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Cache-Control: max-age=600
```

### ❌ Bad — the grant sent only to a CORS request

```http
GET /data HTTP/1.1
Host: api.example.com

HTTP/1.1 200 OK
Cache-Control: max-age=600

GET /data HTTP/1.1
Host: api.example.com
Origin: https://app.example.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://app.example.com
Cache-Control: max-age=600
```
