<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Origin Isolated Header Validity

## Description

Checks the `Origin-Isolation` response header and ensures it uses the structured-header boolean value `?1` to request document origin isolation. The header must be a single value and must not contain comma-separated lists or multiple header fields. `?1` signals that the origin requests origin isolation for documents served from it; other values are rejected by this rule.

## Specifications

- [Origin Isolation Explainer](https://github.com/davidben/origin-isolation/blob/master/README.md): See "Example" and "How it works"
- [RFC 8941 §3](https://www.rfc-editor.org/rfc/rfc8941.html#section-3): Structured Headers boolean values (§3–§4)

## Configuration

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
