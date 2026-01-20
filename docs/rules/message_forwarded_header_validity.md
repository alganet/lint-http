<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Forwarded Header Validity

## Description

Validates `Forwarded` header field-values follow the `Forwarded` header syntax as specified by RFC 7239 §4. Each element MUST be a semicolon-separated list of parameter `name=value` pairs; parameter names MUST be valid tokens. Well-known parameters (`for`, `by`, `proto`, `host`) are checked for syntactic validity (IPv4, bracketed IPv6 with optional port, `unknown`, obfuscated token, or quoted-string).

## Specifications

- [RFC 7239 §4](https://www.rfc-editor.org/rfc/rfc7239.html#section-4): Forwarded header

## Configuration

```toml
[rules.message_forwarded_header_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Forwarded: for=192.0.2.43;proto=https;by=203.0.113.5
Forwarded: for="[2001:db8::1]";host=example.com
```

### ❌ Bad

```http
Forwarded: for=999.999.999.999
# invalid IPv4

Forwarded: for=[2001:db8::zzz]
# invalid IPv6

Forwarded: for
# missing '=' and value

Forwarded: for=192.0.2.1:99999
# invalid port
```
