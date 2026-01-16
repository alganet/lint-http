<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Priority Header Syntax

## Description

The `Priority` header (RFC 9218) conveys priority parameters as a Structured Fields Dictionary. This rule validates basic syntax for the header and enforces the defined semantics for the standard parameters:

- `u` (urgency) MUST be an integer in the range 0..=7 (inclusive).
- `i` (incremental) is a boolean: it may be present without a value (indicating `true`) or use `?1`/`?0` notation. Unknown parameters are allowed and ignored.

Receivers MUST ignore unknown members and parameters; this rule flags clear parsing errors and out-of-range `u` values.

## Specifications

- [RFC 9218 §4–§5 (Priority header and parameters)](https://www.rfc-editor.org/rfc/rfc9218.html)
- [RFC 8941 (Structured Field Values for HTTP)](https://www.rfc-editor.org/rfc/rfc8941.html)

## Configuration

Minimal example to enable the rule in `config.toml`:

```toml
[rules.message_priority_header_syntax]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /image.jpg HTTP/1.1
Priority: u=5, i
```

```http
HTTP/1.1 200 OK
Priority: u=1
```

### ❌ Bad

```http
GET /script.js HTTP/1.1
Priority: u=8
```

```http
Priority: u
```
