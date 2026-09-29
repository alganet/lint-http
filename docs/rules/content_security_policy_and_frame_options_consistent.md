<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Content Security Policy And Frame Options Consistent

## Description

Detect contradictory framing directives between `Content-Security-Policy` (the `frame-ancestors` directive) and `X-Frame-Options`. These headers express framing restrictions; when they conflict, they create ambiguity that may cause different user agents to allow or block framing inconsistently.

A `DENY` beside a policy that names any origin other than `'self'` is not reported: no conforming `X-Frame-Options` value states such a policy, and `DENY` is the fallback that permits a user agent predating `frame-ancestors` nothing the policy forbids.

**An `ALLOW-FROM` origin is matched the way CSP matches it**, not compared as text: a user agent parses the ancestor's origin into a URL and asks whether any source expression matches it (CSP3 §6.4.2.1, §6.7.2.8). So a wildcard host (`https://*.example.com`), a source with no scheme, a scheme alone (`https:`), `*`, a default port written out on either side, and a `'self'` whose `http` origin the `https` origin upgrades are all agreement, while a source carrying a path never matches an origin, whose path is `/`. `'self'` is the request target's origin; where the target does not state its scheme, a disagreement is reported only if it holds under both `http` and `https`.

Note: this check considers only enforceable header-delivered CSP policies (`Content-Security-Policy`); `Content-Security-Policy-Report-Only` is ignored because it does not itself change framing enforcement.

## Violations

- [content_security_policy_frame_ancestors_conflicting](../violations/content_security_policy_frame_ancestors_conflicting.md) — frame-ancestors and X-Frame-Options state different framing policies

## Specifications

- [CSP3 §6.4.2](https://www.w3.org/TR/CSP3/#directive-frame-ancestors): `frame-ancestors` — which URLs may embed the resource, the rough equivalences between its source expressions and `X-Frame-Options`' values, and § 6.4.2.2's statement that an enforced `frame-ancestors` overrides that header outright
- [HTML Speculative Loading](https://html.spec.whatwg.org/multipage/speculative-loading.html#the-x-frame-options-header): HTML Living Standard — `X-Frame-Options` header and its relation to `frame-ancestors`
- [MDN X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options): `X-Frame-Options` — legacy header with values `DENY`, `SAMEORIGIN`, and the obsolete `ALLOW-FROM`. Note: `ALLOW-FROM` is deprecated and not supported by most modern browsers — prefer using CSP's `frame-ancestors` for origin-specific framing policies

## Configuration

```toml
[rules.content_security_policy_and_frame_options_consistent]
enabled = true
```

## Examples

### ✅ Good

```http
Content-Security-Policy: frame-ancestors 'none'
# No X-Frame-Options header present
```

```http
Content-Security-Policy: frame-ancestors https://example.com
X-Frame-Options: ALLOW-FROM https://example.com
```

```http
Content-Security-Policy: frame-ancestors https://*.example.com
X-Frame-Options: ALLOW-FROM https://cms.example.com
# The wildcard host matches the origin ALLOW-FROM names, so both policies permit it
```

```http
Content-Security-Policy: frame-ancestors 'self' https://cms.example
X-Frame-Options: DENY
# No X-Frame-Options value states a list of origins, so DENY is the fallback for user agents that predate frame-ancestors
```

### ❌ Bad

```http
Content-Security-Policy: frame-ancestors 'none'
X-Frame-Options: SAMEORIGIN
# CSP disallows all framing but XFO says allow same origin -> contradiction
```

```http
Content-Security-Policy: frame-ancestors 'self'
X-Frame-Options: DENY
# CSP allows same-origin framing while XFO denies all framing -> contradiction
```
