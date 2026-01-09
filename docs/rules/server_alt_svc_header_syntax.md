<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Alt-Svc Header Syntax

## Description

Validate the `Alt-Svc` response header. Each value must be of the form `protocol=authority` with optional `;` parameters (e.g., `ma`). The `protocol` token must be a valid HTTP `token`, and `authority` should be a non-empty host[:port] or a quoted authority. If a port is present, it must be numeric.

## Specifications

- [RFC 7838](https://www.rfc-editor.org/rfc/rfc7838.html) — Alternative Services

## Configuration

```toml
[rules.server_alt_svc_header_syntax]
enabled = true
severity = "warn"
```

## Examples

✅ Good

```http
Alt-Svc: h2=":443"; ma=2592000
Alt-Svc: h2=example.com:443
Alt-Svc: h2=example.com:443, h3=example.com:8443
Alt-Svc: h2="[::1]:443"
```

❌ Bad

```http
Alt-Svc: h@=example.com:443  # invalid protocol token
Alt-Svc: h2=example.com:notaport  # invalid port
Alt-Svc: h2example.com:443  # missing '='
Alt-Svc: ,  # empty token
```