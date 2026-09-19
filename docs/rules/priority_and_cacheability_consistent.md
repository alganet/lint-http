<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Priority and Cacheability Consistency

## Description

When an origin server includes a `Priority` response header (RFC 9218 §5) it is expected to control the cacheability or applicability of the cached response by using cache-control related fields (for example `Cache-Control` and/or `Vary`). This rule warns when a response includes `Priority` but lacks both, which can lead to a cache handing a response shaped by one request to a different one. **The expectation's subject is the *cached* response, so only an exchange a cache was permitted to store is reported.** RFC 9110 §9.2.3 says a method has to define caching semantics to be cached at all and names `GET`, `HEAD` and `POST`; §9.3.7 ends by saying of one of the others that *"Responses to the OPTIONS method are not cacheable"*, which is the case an operator meets most often, because a `Priority` is commonly stamped on every response an edge serves. RFC 9111 §3's conjunction has to hold besides: a `302` that advertises no freshness is not stored and so is not reported, while a `404` is reported, because §15.1 defines it as heuristically cacheable. `POST` is left out although §9.2.3 names it — §9.3.3 makes a POST response cacheable only where it carries explicit freshness *and* a `Content-Location` equal to the target URI, and a reader that asked only the first term would report a response no cache could have kept. The two caching fields are read by presence alone; the `Priority` value feeds the message and is never parsed as a Dictionary, which is `priority_header_syntax`'s reading.

## Violations

- [priority_cacheability_missing](../violations/priority_cacheability_missing.md) — A Priority response says nothing about caching

## Specifications

- [RFC 9218 §5](https://www.rfc-editor.org/rfc/rfc9218.html#section-5): The `Priority` response header field — an end-to-end signal a server may generate from properties of the request, and the expectation that a server doing so also controls the cacheability of what it sends
- [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html): HTTP caching and `Cache-Control`/`Vary` semantics (informative)

## Configuration

```toml
[rules.priority_and_cacheability_consistent]
enabled = true
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Cache-Control: public, max-age=60
Priority: u=3

<body...>
```

### ✅ Good (Vary is present)

```http
HTTP/1.1 200 OK
Vary: Accept-Encoding
Priority: u=1

<body...>
```

### ✅ Good (OPTIONS — §9.3.7: responses to OPTIONS are not cacheable)

```http
OPTIONS /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Allow: GET, HEAD, OPTIONS
Priority: u=3, i=?0
```

### ✅ Good (302 — advertises no freshness, and §15.1 does not name it)

```http
HTTP/1.1 302 Found
Location: https://example.com/elsewhere
Priority: u=3
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Priority: u=2

<body...>
```

### ❌ Bad (404 — §15.1 defines it as heuristically cacheable)

```http
HTTP/1.1 404 Not Found
Priority: u=3

<body...>
```
