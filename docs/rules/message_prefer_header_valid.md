<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Prefer header syntax

## Description

Validate that the `Prefer` request header follows the ABNF in RFC 7240 §2. Each preference token must be a `token` and optional values must be either a `token` or a `quoted-string`. Parameters (semicolon-separated) must have `token` names and their values must be `token` or `quoted-string` when present.

## Specifications

- [RFC 7240 §2](https://www.rfc-editor.org/rfc/rfc7240#section-2) — Prefer header syntax and semantics.

## Configuration

```toml
[rules.message_prefer_header_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
POST /items HTTP/1.1
Host: example.org
Prefer: respond-async

POST /items HTTP/1.1
Host: example.org
Prefer: return=representation; foo="bar"

POST /items HTTP/1.1
Host: example.org
Prefer: handling=lenient, wait=100
```

### ❌ Bad

```http
POST /items HTTP/1.1
Host: example.org
Prefer: =foo   # empty token

POST /items HTTP/1.1
Host: example.org
Prefer: "quoted"   # token must not be quoted

POST /items HTTP/1.1
Host: example.org
Prefer: return="bad\x01"  # control characters inside quoted-string
```
