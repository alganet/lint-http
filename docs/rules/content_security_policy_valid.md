<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Content Security Policy Valid

## Description

Validate basic `Content-Security-Policy` syntax in responses. This rule checks that the header value is UTF-8, not empty, directives are present and well-formed (directive names follow CSP's `directive-name = 1*( ALPHA / DIGIT / "-" )` grammar — narrower than the HTTP `token`), and common structural issues are flagged (unterminated single-quoted keywords, empty directives due to trailing semicolons, empty nonces/hashes).

This rule is intentionally conservative: it is not a full CSP grammar validator, but catches common, obvious mistakes and misconfigurations.

## Specifications

- [CSP3](https://www.w3.org/TR/CSP3/): W3C Content Security Policy Level 3 — directive and source-list syntax
- [CSP3 §2.2](https://www.w3.org/TR/CSP3/#framework-policy): Policies: `serialized-policy = serialized-directive *( optional-ascii-whitespace ";" [ optional-ascii-whitespace serialized-directive ] )` — one unbracketed directive and any number of bracketed ones, which is what decides whether a given `;` names anything
- [CSP3 §2.3](https://www.w3.org/TR/CSP3/#framework-directives): Directives: `directive-name = 1*( ALPHA / DIGIT / "-" )`, letters, digits and a hyphen and nothing else — where an HTTP `token` also admits `_`, `.` and a dozen other marks
- [CSP3 §2.3.1](https://www.w3.org/TR/CSP3/#framework-directive-source-list): Source Lists: `source-expression`, the `nonce-source` and `hash-source` productions whose single quotes are written *inside* them, and the `base64-value` both of them carry
- [MDN Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy): Mozilla MDN overview and directive examples

## Configuration

```toml
[rules.content_security_policy_valid]
enabled = true
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Content-Security-Policy: default-src 'self'; script-src 'nonce-abc123' https://example.com; upgrade-insecure-requests
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Content-Security-Policy:
```

```http
HTTP/1.1 200 OK
Content-Security-Policy: def@ult-src 'self'
```

```http
HTTP/1.1 200 OK
Content-Security-Policy: default-src 'self';
```

```http
HTTP/1.1 200 OK
Content-Security-Policy: default-src 'self
```
