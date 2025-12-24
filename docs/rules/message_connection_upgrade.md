<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Connection Upgrade

## Description

If the `Connection` header nominates the `upgrade` token (for example, `Connection: upgrade` or `Connection: keep-alive, upgrade`), an `Upgrade` header field MUST be present. This rule flags messages that indicate a protocol upgrade in `Connection` but do not carry an `Upgrade` header.

Missing the `Upgrade` header while advertising `upgrade` in `Connection` can cause endpoints to misinterpret upgrade intentions and lead to protocol errors.

## Specifications

- [RFC 9110 §7.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8): Upgrade header

## Configuration

```toml
[rules.message_connection_upgrade]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Connection: upgrade
Upgrade: websocket
```

### ❌ Bad

```http
Connection: upgrade
# Missing Upgrade header
```
