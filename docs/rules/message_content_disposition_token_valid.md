<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Content-Disposition Disposition-Type Token Valid

## Description

Validate that the `Content-Disposition` header's `disposition-type` is a valid `token` and not empty. The `disposition-type` appears before any `;` parameter list (e.g., `attachment; filename="a.txt"`) and must follow the `token` grammar (no whitespace, control, or special characters).

## Specifications

- [RFC 6266 §4](https://www.rfc-editor.org/rfc/rfc6266.html#section-4) — Use of `Content-Disposition` in HTTP (disposition-type is a `token` and followed by optional parameters)

## Configuration

Enable this rule in your `config.toml`:

```toml
[rules.message_content_disposition_token_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Content-Disposition: attachment; filename="example.txt"
```

```http
Content-Disposition: inline
```

### ❌ Bad

```http
Content-Disposition: ; filename="example.txt"
```

```http
Content-Disposition: bad@type; filename="a"
```
