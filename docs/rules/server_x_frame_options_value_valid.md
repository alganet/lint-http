<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# server_x_frame_options_value_valid

## Description

The `X-Frame-Options` response header protects content from being embedded in frames by other origins. This rule validates that the header, when present, uses one of the allowed values: `DENY`, `SAMEORIGIN`, or `ALLOW-FROM <serialized-origin>`. It also rejects multiple header occurrences and malformed `ALLOW-FROM` origins.

## Specifications

- [RFC 7034 §2.1](https://www.rfc-editor.org/rfc/rfc7034.html#section-2.1) — `X-Frame-Options` header values: `DENY`, `SAMEORIGIN`, or `ALLOW-FROM <serialized-origin>`.
- [RFC 6454 §6](https://www.rfc-editor.org/rfc/rfc6454.html#section-6) — `serialized-origin` syntax (`scheme://host[:port]`).

## Configuration

Minimal example to enable this rule in your TOML config:

```toml
[rules.server_x_frame_options_value_valid]
enabled = true
severity = "warn"
```

## Examples

✅ Good

```http
HTTP/1.1 200 OK
X-Frame-Options: DENY

...response body...
```

```http
HTTP/1.1 200 OK
X-Frame-Options: ALLOW-FROM https://example.com/

...response body...
```

❌ Bad

```http
HTTP/1.1 200 OK
X-Frame-Options: ALLOW-FROM example.com

...response body...
```

```http
HTTP/1.1 200 OK
X-Frame-Options: DENY, SAMEORIGIN

...response body...
```

```http
HTTP/1.1 200 OK
X-Frame-Options: SOMETHINGELSE

...response body...
```
