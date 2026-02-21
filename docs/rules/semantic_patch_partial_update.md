<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# semantic_patch_partial_update

## Description

The `PATCH` method is defined for applying partial modifications to an
existing resource.  The request entity is not the new resource state, but a
"patch document" whose semantics are dictated by its media type.  If a
client sends a body with a `PATCH` request, the corresponding `Content-Type`
header field MUST describe a patch format; otherwise, the server cannot
interpret the change instructions and the request is likely to fail or cause
unexpected effects.

This rule flags `PATCH` requests that include a body but either lack a
`Content-Type` header altogether or use a media type that does not indicate a
patch document (for example, a type or subtype that does not contain the
token `patch`).  If a `Content-Type` header is present but cannot be
interpreted as UTF-8 or is otherwise syntactically invalid, the rule does not
raise a violation; such problems are covered by the general
`message_content_type_well_formed` rule.

## Specifications

- [RFC 5789 §2](https://www.rfc-editor.org/rfc/rfc5789.html#section-2) — Patch
  method semantics and patch document media types.

## Configuration

```toml
[rules.semantic_patch_partial_update]
enabled = true
severity = "error"
```

## Examples

### ✅ Good

```http
PATCH /widgets/123 HTTP/1.1
Host: example.com
Content-Type: application/json-patch+json
Content-Length: 48

[ { "op": "replace", "path": "/qty", "value": 20 } ]
```

### ✅ Also good (bodyless PATCH is ignored by this rule)

```http
PATCH /widgets/123 HTTP/1.1
Host: example.com
```

### ❌ Bad — no `Content-Type` while body is present

```http
PATCH /widgets/123 HTTP/1.1
Host: example.com
Content-Length: 5

hello
```

### ❌ Bad — `Content-Type` not a patch media type

```http
PATCH /widgets/123 HTTP/1.1
Host: example.com
Content-Type: text/plain
Content-Length: 7

update!
```