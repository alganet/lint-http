<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful Cache Validation Chain

## Description

Caches must validate stored responses using up-to-date validators.  When a
server supplies an `ETag` or `Last-Modified` header, a well-behaved cache will
include that validator in subsequent conditional requests (`If-None-Match` or
`If-Modified-Since`).  The value in those request headers should match the
most recently observed validator for the resource; if it does not,
revalidation may fail and clients can receive stale or unexpected content.

This rule applies weak comparison semantics for entity-tags, meaning a weak
ETag (`W/"tag"`) is considered equivalent to its strong counterpart when the
opaque tag matches.

This rule examines the recorded history for the same client+resource and
recomputes the current validator, taking into account updates that may arrive
in `304 Not Modified` responses.  If the current request contains a
conditional header whose value does not match the known validator, a violation
is raised.  The rule ignores requests that are not conditional and situations
where no validator was ever seen.

## Specifications

- [RFC 9111 §4.3 "Caching Negotiated Responses" (validator semantics)](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3)
- [RFC 9110 §13.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.2) (If-None-Match)
- [RFC 9110 §13.1.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.3) (If-Modified-Since)

## Configuration

```toml
[rules.stateful_cache_validation_chain]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good Sequence

**Previous Response:**
```http
HTTP/1.1 200 OK
ETag: "abc"
```

**Current Request:**
```http
GET /resource HTTP/1.1
Host: example.com
If-None-Match: "abc"
```

The request validator matches the most recent ETag; no violation is reported.

### ❌ Bad Request

**History (most recent first):**
```http
HTTP/1.1 304 Not Modified
ETag: "xyz"  # validator updated by 304

HTTP/1.1 200 OK
ETag: "abc"
```

**Current Request:**
```http
GET /resource HTTP/1.1
Host: example.com
If-None-Match: "abc"
```

The cache should have used `"xyz"`, not the stale `"abc"` value; a warning is
emitted.
