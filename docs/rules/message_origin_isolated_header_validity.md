<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_origin_isolated_header_validity

## Description

Checks the `Origin-Isolation` response header and ensures it uses the structured-header boolean value `?1` to request document origin isolation. The header must be a single value and must not contain comma-separated lists or multiple header fields. `?1` signals that the origin requests origin isolation for documents served from it; other values are rejected by this rule.

## Specifications

- Origin Isolation explainer: https://github.com/davidben/origin-isolation/blob/master/README.md (See "Example" and "How it works")
- Structured Headers boolean values: https://www.rfc-editor.org/rfc/rfc8941.html (RFC 8941 §3–§4)

## Configuration

TOML snippet to enable the rule (disabled by default):

```toml
[rules.message_origin_isolated_header_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Origin-Isolation: ?1
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Origin-Isolation: ?0
```

```http
HTTP/1.1 200 OK
Origin-Isolation: ?1, ?1
```

```http
HTTP/1.1 200 OK
Origin-Isolation: unsafe-none
```
