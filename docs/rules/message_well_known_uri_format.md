<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_well_known_uri_format

Ensure that URIs intended to be well-known resources follow the `/.well-known/` path convention. The Well-Known URIs specification defines a small, well-known path prefix to host discovery endpoints and other site-level resources.

## Description

Requests that target site-wide well-known resources MUST use a path starting with `/.well-known/` followed by the resource name. Requests that use `/.well-known` without the trailing slash and name, or that include `/.well-known` at a non-root path (for example, `/foo/.well-known/bar`) are likely misconfigured and should be corrected.

## Specifications

- [RFC 8615 §3 — Well-Known URIs](https://www.rfc-editor.org/rfc/rfc8615.html#section-3)

## Configuration

TOML configuration example:

```toml
[rules.message_well_known_uri_format]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /.well-known/openid-configuration HTTP/1.1
Host: example.com
```

```http
GET https://example.com/.well-known/security.txt HTTP/1.1
```

### ❌ Bad

```http
GET /.well-known HTTP/1.1
Host: example.com
```

```http
GET /foo/.well-known/bar HTTP/1.1
Host: example.com
```

