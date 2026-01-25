<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message X-Forwarded Consistency

## Description

Validate common `X-Forwarded-*` headers for well-formedness and basic consistency. This rule checks that:

- `X-Forwarded-For` contains only IP addresses (or the token `unknown`),
- `X-Forwarded-Proto` uses a supported scheme (`http` or `https`), and
- `X-Forwarded-Host` contains a syntactically valid host (optionally with port, or bracketed IPv6 with optional port).

These checks help detect misconfigured proxies that may produce malformed or misleading forwarding headers. Note: RFC 7239 specifies the standardized `Forwarded` header as a replacement for ad-hoc `X-Forwarded-*` headers; this rule validates the widely-used legacy `X-Forwarded-*` fields for basic correctness.

## Specifications

- [RFC 7239 §4](https://www.rfc-editor.org/rfc/rfc7239.html#section-4): `Forwarded` header syntax (standardized alternative to `X-Forwarded-*`).

- Practical usage: `X-Forwarded-For` is commonly used to record client addresses in order; this rule conservatively accepts `unknown` token for cases where the sender can't be determined.

## Configuration

Minimal example to enable this rule:

```toml
[rules.message_x_forwarded_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET / HTTP/1.1
Host: example.com
X-Forwarded-For: 203.0.113.195, 198.51.100.17
X-Forwarded-Proto: https
X-Forwarded-Host: example.com:443
```

### ❌ Bad

```http
GET / HTTP/1.1
Host: example.com
X-Forwarded-For: not-an-ip
# invalid X-Forwarded-For member, not a valid IP address
```

```http
GET / HTTP/1.1
Host: example.com
X-Forwarded-Proto: ftp
# unsupported proto (only http/https are accepted)
```

```http
GET / HTTP/1.1
Host: example.com
X-Forwarded-Host: user@host
# invalid host (contains userinfo)
```