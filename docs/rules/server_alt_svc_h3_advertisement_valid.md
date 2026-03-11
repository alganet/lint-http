<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Alt-Svc H3 Advertisement Valid

## Description

Validates `Alt-Svc` entries that advertise HTTP/3. Servers must use the final ALPN protocol identifier `h3`, not draft-era tokens such as `h3-29` or `h3-Q050`. When the `ma` (max-age) parameter is present on an `h3` entry, its value must be a positive integer within reasonable bounds (at most 1 year / 31 536 000 seconds); `ma=0` immediately invalidates the advertisement and is flagged as likely misconfiguration.

This rule complements `server_alt_svc_header_syntax` (general syntax) and `server_alt_svc_protocol_iana_registered` (allowlist check) by adding HTTP/3-specific semantic validation.

## Specifications

- [RFC 9114 §3.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-3.1) — HTTP/3 alternative service discovery
- [RFC 7838 §3](https://www.rfc-editor.org/rfc/rfc7838.html#section-3) — Alt-Svc header field syntax and `ma` parameter semantics

## Configuration

```toml
[rules.server_alt_svc_h3_advertisement_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Alt-Svc: h3=":443"; ma=2592000
Alt-Svc: h3=example.com:443; ma=86400
Alt-Svc: h2=":443", h3=":443"; ma=3600
```

### ❌ Bad

```http
Alt-Svc: h3-29=":443"              # draft protocol identifier
Alt-Svc: h3=":443"; ma=0           # immediately invalidates entry
Alt-Svc: h3=":443"; ma=99999999    # exceeds 1 year
Alt-Svc: h3=":443"; ma=abc         # non-numeric max-age
```
