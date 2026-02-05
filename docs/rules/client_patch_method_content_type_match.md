<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client PATCH Content-Type Matches Accept-Patch

## Description

When a server advertises supported patch formats using `Accept-Patch`, clients issuing `PATCH` requests SHOULD include a `Content-Type` that matches one of the advertised media types. This rule flags `PATCH` requests whose `Content-Type` does not match any media type previously advertised in an `Accept-Patch` response. It helps avoid unexpected or unsupported patch document formats (RFC 5789 §2.2).

## Specifications

- [RFC 5789 §2.2](https://www.rfc-editor.org/rfc/rfc5789.html#section-2.2) — `PATCH` and `Accept-Patch` header; Accept-Patch advertises supported patch media types.

## Configuration

```toml
[rules.client_patch_method_content_type_match]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
# Previous response included an Accept-Patch advertising merge-patch+json
HTTP/1.1 200 OK
Accept-Patch: application/merge-patch+json

# Client PATCH uses a matching Content-Type
PATCH /resource HTTP/1.1
Content-Type: application/merge-patch+json

{ "op": "replace", "path": "/name", "value": "x" }
```

### ❌ Bad

```http
# Previous response advertised application/merge-patch+json
HTTP/1.1 200 OK
Accept-Patch: application/merge-patch+json

# Client PATCH uses a different Content-Type -> violation
PATCH /resource HTTP/1.1
Content-Type: application/json

{ "name": "x" }
```
