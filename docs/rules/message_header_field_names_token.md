<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Header Field Names Token

## Description

This rule validates that **header field-names** conform to the `token` grammar (RFC 7230 §3.2). Field-names containing control characters, spaces, or other separator characters are invalid and can indicate protocol violations or injection attempts.

The rule flags header names that contain characters outside the allowed `tchar` set (letters, digits, and the following characters: ``! # $ % & ' * + - . ^ _ ` | ~``).

## Specifications

- [RFC 7230 §3.2](https://www.rfc-editor.org/rfc/rfc7230.html#section-3.2): Field syntax and header field naming

## Configuration

```toml
[rules.message_header_field_names_token]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Host: example.com
Content-Type: text/plain
X-Custom-Header: v
```

### ❌ Bad

```http
Bad Header: v
X@Bad: v
header:with:colon: v
```
