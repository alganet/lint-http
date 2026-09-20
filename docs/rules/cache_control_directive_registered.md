<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Cache-Control Directive IANA-Registered

## Description

Read each `Cache-Control` directive name and ask whether it identifies a directive any cache implements.

**A cache MUST ignore what it does not recognise**, which is what makes this worth reporting rather than tolerating. RFC 9111 §5.2.3 says *"A cache MUST ignore unrecognized cache directives"*, so an unregistered name is not a weaker instruction — it is no instruction at all, and every cache on the path behaves as though the sender had written nothing. `Cache-Control: public, max-age=300, s-max-age=150` asks shared caches for 150 seconds and gets 300, because `s-maxage` is the registered name and `s-max-age` is one hyphen away from it.

**The list ships complete, and stays configuration anyway.** RFC 9111 §5.2.4 puts the *"Hypertext Transfer Protocol (HTTP) Cache Directive Registry"* under IETF Review, so a new directive arrives with an RFC rather than between two of them — which is why the default is the whole registry, where `alt_svc_protocol_registered` next door can only ask an operator what its deployment serves. A deployment running a private extension its own caches implement adds the name, and that addition is exactly the claim the finding rests on.

**The comparison folds case and nothing else.** §5.2 says directives are *"identified by a token, to be compared case-insensitively"*, so `NO-STORE` is `no-store` here as it is in every cache. The argument is not read at all: whether `max-age` carries digits is the directive's own syntax and `cache_control_directive_valid`'s question.

**What this rule declines.** Everything that is the field's grammar rather than its namespace: an empty list element, a directive name that is no `token`, a name holding whitespace or a control character. `cache_control_directive_valid` and `cache_control_token_valid` read the same list under the same scope and report all three, so a member this rule cannot name a directive from is passed over rather than reported twice. Both sides of the exchange are read, because §5.2 lists directives for caches along the request/response chain and a client writing `only-if-cachd` has made the same mistake an origin does.

## Violations

- [cache_control_directive_unregistered](../violations/cache_control_directive_unregistered.md) — A Cache-Control directive names nothing any cache implements

## Specifications

- [RFC 9111 §5.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2): Cache-Control directives and general directive syntax — `cache-directive = token [ "=" ( token / quoted-string ) ]`, the production an argument's presence and form derive from
- [RFC 9111 §5.2.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.3): Extension Directives — a cache MUST ignore what it does not recognise, and a new directive states whether it requires an argument, what a missing one means, and what a present one means where none is defined
- [RFC 9111 §5.2.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.4): Cache Directive Registry — the "Hypertext Transfer Protocol (HTTP) Cache Directive Registry" defines the namespace for the cache directives, and a name enters it under IETF Review rather than by being sent

## Configuration

```toml
[rules.cache_control_directive_registered]
enabled = true
# The "Hypertext Transfer Protocol (HTTP) Cache Directive Registry", which RFC
# 9111 § 5.2.4 says defines the namespace for cache directives. A name outside
# it is one every cache MUST ignore, so what the sender asked for does not
# happen — `s-max-age=150` beside `max-age=300` gives shared caches 300.
#
# Unlike the ALPN list next door, this one ships complete: § 5.2.4 puts the
# namespace under IETF Review, so a directive arrives with an RFC rather than
# between two of them. The 16 below are the whole registry — RFC 9111's
# fourteen, RFC 5861's two — plus RFC 8246's `immutable`.
#
# Extend it where a deployment runs a private directive its own caches
# implement. Adding a name here is the claim that something on this path acts
# on it, which is the claim the finding rests on.
allowed = [
    "max-age",
    "max-stale",
    "min-fresh",
    "must-revalidate",
    "must-understand",
    "no-cache",
    "no-store",
    "no-transform",
    "only-if-cached",
    "private",
    "proxy-revalidate",
    "public",
    "s-maxage",
    "immutable",
    "stale-if-error",
    "stale-while-revalidate",
]
```

## Examples

### ✅ Good

```http
Cache-Control: public, max-age=300, s-maxage=150
```

### ✅ Good (the registry is not RFC 9111 alone)

```http
Cache-Control: max-age=600, immutable, stale-while-revalidate=30
```

### ✅ Good (names are compared case-insensitively)

```http
Cache-Control: NO-STORE
```

### ❌ Bad — `s-maxage` is the name; shared caches use max-age=300 instead

```http
Cache-Control: public, max-age=300, s-max-age=150
```

### ❌ Bad — two directives no cache has ever implemented

```http
Cache-Control: no-cache, post-check=0, pre-check=0
```

### ❌ Bad — a request directive is a directive too

```http
GET / HTTP/1.1
Host: example.com
Cache-Control: only-if-cachd
```
