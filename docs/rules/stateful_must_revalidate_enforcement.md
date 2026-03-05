<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful must-revalidate enforcement

## Description

The `must-revalidate` cache-control directive (RFC 9111 §5.2.2.2) tells
caches that once a stored response becomes stale it **must not** be used to
satisfy subsequent requests unless the entry has been successfully
revalidated with the origin server.  Serving a stale value without revalidation
can expose clients to outdated or incorrect data.

This rule reconstructs a small piece of cache state for a given client+resource
by locating the most recent prior response that included
`Cache-Control: must-revalidate`.  It estimates the age of that entry using the
`Age` header (if any) plus the time elapsed since the response was observed.
The advertised freshness lifetime is taken from a `max-age` directive, if
present, or else from an `Expires` header; replies that provide neither are
considered immediately stale.  If the computed age exceeds or **equals** the freshness
lifetime (a zero lifetime is therefore immediately stale) *and* the current
request is unconditional (no `If-None-Match` or `If-Modified-Since`) and the
original response carried a validator, the rule raises a warning.  Directive
names in `Cache-Control` are parsed case-insensitively, so `Max-Age` or
`MAX-AGE` are treated the same as the canonical lowercase form.  Clients that lack validators are not flagged because they
have no way to revalidate.

This stateful check complements the existing
`stateful_max_age_directive_validity` rule by covering situations where
`must-revalidate` is present but no explicit `max-age` is provided (stale
data is prohibited immediately), and by emphasising the intent of the
`must-revalidate` directive when both rules are enabled.

## Specifications

- [RFC 9111 §5.2.2.2 — `must-revalidate`](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.2)
- [RFC 9111 §4.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2) — Calculating the age of a response
- [RFC 9111 §4.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3) — Expiration model (freshness lifetime)

## Configuration

```toml
[rules.stateful_must_revalidate_enforcement]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good — fresh entry reused without conditional headers

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=60, must-revalidate

# thirty seconds later the cache is still fresh and may satisfy a request
# without conditional headers.  The linter does not observe a violation.
```

### ✅ Good — stale entry revalidated

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=1, must-revalidate
< ETag: "v1"

# later, after expiry:
> GET /resource HTTP/1.1
> Host: example.com
> If-None-Match: "v1"    # conditional request used
```

### ✅ Good — must-revalidate with no freshness never reused

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: must-revalidate
< ETag: "v2"

# client must revalidate on every request; a conditional request is fine
> GET /resource HTTP/1.1
> Host: example.com
> If-None-Match: "v2"
```

### ❌ Bad — stale entry reused without conditional request

```http
> GET /resource HTTP/1.1
> Host: example.com

< HTTP/1.1 200 OK
< Cache-Control: max-age=1, must-revalidate
< ETag: "v1"

# several seconds later the client fetches again but omits validators
> GET /resource HTTP/1.1
> Host: example.com
# violation: stale according to must-revalidate semantics
```
