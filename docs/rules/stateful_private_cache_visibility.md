<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful private cache visibility

## Description

Responses with `Cache-Control: private` are intended for a single user
agent's private cache and **must not be stored or served** by shared caches
(RFC 9111 §5.2).  If a shared cache accidentally retains such a response,
other clients may later receive the representation, violating privacy and
correctness expectations.

This stateful rule examines a sequence of transactions for the same resource
across **all clients**.  When a request includes a conditional validator
(ETag or Last-Modified) that matches a value previously seen in a response
carrying the `private` directive **and** that earlier response was sent to a
**different** client, we infer that some intermediate cache reused the
private entry.  A warning is emitted in that case.

The rule relies on a cross-client history; the engine handles this by
scoping the query to all clients for the resource rather than the default
per-client history.  Only conditional requests trigger the check, since they
provide tangible evidence that a particular validator value was reused.

## Specifications

- [RFC 9111 §5.2 — Cache-Control field semantics](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2) — `private` directive applies only to private caches.

## Configuration

```toml
[rules.stateful_private_cache_visibility]
enabled = true
severity = "warn"
```

## Examples

### ❌ Bad — another client revalidates using a private response

```
> GET /secret HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: private
< ETag: "s1"

# later, a different client sends a conditional request using that ETag
> GET /secret HTTP/1.1
> Host: example.com
> If-None-Match: "s1"   # value originated in private response for another client
```

A violation is reported when the second request is processed because a
shared cache must not have exposed the private response to the second
client.

### ✅ Good — only same client reuses the validator

```
> GET /secret HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: private
< ETag: "s1"

# the same client later revalidates
> GET /secret HTTP/1.1
> Host: example.com
> If-None-Match: "s1"   # acceptable, private cache may retain its own entry
```

