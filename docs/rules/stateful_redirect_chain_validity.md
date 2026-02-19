<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful Redirect Chain Validity

## Description

Detects obvious redirect loops and repeated redirect targets for the same client+resource. The rule flags:

- Immediate circular redirects where the `Location` header points back to the same request target (absolute or relative).
- Repeated redirects for the same client+resource that point to the same `Location` as a previous response (likely misconfiguration or loop).

This is a conservative, high‑value stateful check — full multi-resource chain graph analysis is out of scope for the current per-resource state store.

## Specifications

- [RFC 9110 §6.4 — Redirection](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4)

## Configuration

```toml
[rules.stateful_redirect_chain_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
> GET /resource HTTP/1.1

< 301 Moved Permanently  HTTP/1.1
< Location: /other
```

### ❌ Bad — Location equals request target (circular)

```http
> GET /resource HTTP/1.1

< 301 Moved Permanently  HTTP/1.1
< Location: /resource
```

### ❌ Bad — same resource repeatedly redirects to same Location

```http
// previous transaction for client requested /r -> 302 Location: /x

> GET /r HTTP/1.1

< 302 Found  HTTP/1.1
< Location: /x
```

