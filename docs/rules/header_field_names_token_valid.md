<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Header Field Names Token Valid

## Description

This rule validates that **field names** conform to the `token` grammar. Field names containing control characters, spaces, or other separator characters are invalid and can indicate protocol violations or injection attempts.

The rule flags field names that contain characters outside the allowed `tchar` set (letters, digits, and the following characters: ``! # $ % & ' * + - . ^ _ ` | ~``). One grammar governs every field section, so the request and response header sections are checked and so are their trailer sections when the message framing carried one.

An HTTP/1.1 field name that is not a `token` is rejected by the message parser before the linter sees it, so this check has teeth on HTTP/2 and HTTP/3: their field-name encodings can convey a `"`, which the `token` grammar does not allow, and RFC 9113 §8.2.1 asks a recipient to validate the name against RFC 9110 §5.1 and treat a message carrying a prohibited character as malformed.

## Specifications

- [RFC 9110 §5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.1): Field Names (field-name = token)
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens (the tchar set the production expands to)
- [RFC 9110 §6.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5): Trailer Fields
- [RFC 9113 §8.2.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.1): Field Validity (HTTP/2 recipients validate names against §5.1)
- [RFC 9114 §4.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2): HTTP Fields (HTTP/3 defers field-name properties to §5.1)

## Configuration

```toml
[rules.header_field_names_token_valid]
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

### ❌ Bad HTTP/2 or HTTP/3, where the field-name encoding conveys a DQUOTE

```http
x"bad: v
```

### ❌ Bad Trailer section, governed by the same grammar

```http
x"checksum: abc123
```
