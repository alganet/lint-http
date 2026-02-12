<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Alt-Svc Protocol IANA-Registered

## Description

Validate `Alt-Svc` response header protocol identifiers. Each `protocol` token (the left-hand side of `protocol=authority`) should be a valid `token` and should be IANA-registered or explicitly allowed via configuration (e.g., `h2`, `h3`). This prevents advertising unsupported or mistyped protocol identifiers to clients.

## Specifications

- [RFC 7838](https://www.rfc-editor.org/rfc/rfc7838.html) — Alternative Services (syntax and semantics)

## Configuration

```toml
[rules.server_alt_svc_protocol_iana_registered]
enabled = true
severity = "warn"
allowed = ["h2", "h3", "h2c", "ws", "wss"]
```

The `allowed` array is required and lists the protocol identifiers your deployment accepts in `Alt-Svc`.

## Examples

### ✅ Good

```http
Alt-Svc: h2=":443"; ma=2592000
Alt-Svc: h3=example.com:8443
Alt-Svc: H2=example.com:443  # protocol tokens are case-insensitive
```

### ❌ Bad

```http
Alt-Svc: xproto=example.com:443   # protocol not in allowlist
Alt-Svc: h@=example.com:443      # invalid protocol token character
```