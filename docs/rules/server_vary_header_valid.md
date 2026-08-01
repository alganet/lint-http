<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Vary Header Valid

## Description

Validate the `Vary` response header against its grammar `Vary = #( "*" / field-name )` (RFC 9110 §12.5.5). This rule enforces that:

- Each field-name conforms to the `token` grammar (RFC `tchar`).
- The list contains no empty elements (a stray, leading, or trailing comma).

Because `Vary` is a comma-separated (`#`) list, an entirely empty value is a legal zero-element list and is not flagged. The wildcard `*` is an ordinary list member: under RFC 9110 it may appear alongside field-names, so the combination is not reported (RFC 7231's `"*" / 1#field-name` exclusivity no longer applies).

## Specifications

- [RFC 9110 §12.5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.5): Vary = #( "*" / field-name ) — a comma-separated list; "*" is an ordinary member (RFC 7231's "*"-or-a-list form is obsolete). Not checked: the same section's "A proxy MUST NOT generate \"*\"", since a forwarded "*" is indistinguishable from a generated one in an observed response

## Configuration

```toml
[rules.server_vary_header_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Vary: Accept-Encoding
Vary: User-Agent
```

```http
Vary: Accept-Encoding, User-Agent
```

```http
Vary: *
```

### ✅ Good — '*' may accompany field-names under RFC 9110

```http
Vary: *, Accept-Encoding
```

### ❌ Bad

```http
Vary: x@bad                # invalid token characters in field-name
Vary: Accept-Encoding,     # empty element (trailing comma) is invalid
```
