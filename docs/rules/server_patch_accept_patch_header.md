<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Accept-Patch Header

## Description

Servers SHOULD include `Accept-Patch` in responses to `PATCH` requests to advertise supported patch media types. This rule checks responses to `PATCH` requests and flags missing or malformed `Accept-Patch` header values.

## Specifications

- [RFC 5789 §2.2](https://www.rfc-editor.org/rfc/rfc5789.html#section-2.2) — PATCH and Accept-Patch header

## Configuration

```toml
[rules.server_patch_accept_patch_header]
enabled = true
severity = "warn"
```

## Examples

✅ Good

```http
Accept-Patch: application/example-patch+json
Accept-Patch: application/example-patch+json, application/merge-patch+json
```

❌ Bad

```http
Accept-Patch: badmedia
(no Accept-Patch header in response to PATCH)
```
