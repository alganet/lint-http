<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful OAuth2 Authorization Code Flow

## Description

The OAuth 2.0 authorization code flow **recommends** (SHOULD) that
clients generate and include a `state` parameter in the initial authorization
request to bind the request and eventual callback.  When the server echoes an
authorization `code`, it is required to return the same `state` value **only if**
the request contained one (RFC 6749 §4.1.1).  The parameter is optional in the
spec, but omitting it leaves the flow vulnerable to CSRF/replay attacks.

This rule therefore treats a request or callback that either lacks a `state`
parameter or provides an empty/whitespace value as a violation, enforcing a
best‑practice requirement that a meaningful state be correlated.

This value prevents cross-site request forgery (CSRF) and replay attacks by
ensuring the callback corresponds to a request the client actually initiated.
Without this correlation, a malicious site could trick the user agent into
sending a `code` it did not request, allowing the attacker to hijack the
authorization grant.

The lint rule observes outgoing requests from a user agent.  It records any
`state` seen in authorization requests and, when a later request carries an
authorization `code`, verifies that a matching `state` occurred previously.
Violations are raised for missing `state` parameters in either direction or
when the callback contains a value not previously observed.

The check does not assume the authorization request and callback share a
common origin; the redirect is typically to the client's own domain while the
initial request targets the identity provider.

## Specifications

- [RFC 6749 §4.1.1 — Authorization Request](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.1)
  (state parameter is **RECOMMENDED**; server must echo if present)

## Configuration

```toml
[rules.stateful_oauth2_code_flow]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

Client includes a non‑empty `state` parameter in the authorization request and
the callback echoes the same value.

```http
> GET /authorize?response_type=code&client_id=1&state=xyz HTTP/1.1
> Host: idp.example.com

< HTTP/1.1 302 Found
< Location: https://app.example.com/callback?code=abc&state=xyz
```

### ❌ Bad — request missing or empty state

```http
> GET /authorize?response_type=code&client_id=1 HTTP/1.1
> Host: idp.example.com
```

Empty or whitespace values such as `state=` also trigger this violation.

### ❌ Bad — callback missing or empty state

```http
> GET /callback?code=abc HTTP/1.1
> Host: app.example.com
```

A callback with `state=` or `state=   ` is treated the same as missing.

### ❌ Bad — unmatched state

(Callback `state` does not match any prior authorization request.)

```http
> GET /callback?code=abc&state=wrong HTTP/1.1
> Host: app.example.com
```