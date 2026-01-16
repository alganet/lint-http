<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Deprecation Header Syntax

## Description

The `Deprecation` response header signals that a resource is deprecated. RFC 9745 defines the header as a Structured Field `Date` item (a numeric timestamp expressed as `@<seconds>`). This rule validates the canonical structured form and flags legacy or invalid forms (literal `true`, HTTP-date, non-numeric `@` values) with helpful messages.

## Specifications

- [RFC 9745 §2 — The `Deprecation` HTTP Response Header Field](https://www.rfc-editor.org/rfc/rfc9745.html#section-2)
- [RFC 9651 §3.3.7 — Structured Field `Date` item syntax](https://www.rfc-editor.org/rfc/rfc9651.html#section-3.3.7)

## Configuration

```toml
[rules.server_deprecation_header_syntax]
# enabled = true
# severity = "warn" # info|warn|error
```

## Examples

### ✅ Good

```http
Deprecation: @1688169599
Deprecation:   @0
```

### ❌ Bad

```http
Deprecation: true
Deprecation: Wed, 11 Nov 2015 07:28:00 GMT
Deprecation: @
Deprecation: @-1
Deprecation: @abc
```

