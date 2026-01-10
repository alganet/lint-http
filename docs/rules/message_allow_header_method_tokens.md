<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Allow Header Method Tokens

## Description

Validate the `Allow` header. This rule enforces that:

- When present, `Allow` MUST be a comma-separated list of valid method tokens.
- Each method token must conform to the `token` grammar (RFC `tchar`).
- Empty tokens are not allowed (e.g., from trailing commas or double commas).

## Specifications

- [RFC 9110 §7.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1.1) — Allow header field
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2) — Token syntax (tchar)

## Configuration

```toml
[rules.message_allow_header_method_tokens]
enabled = true
severity = "error"
```

## Examples

✅ Good

```http
Allow: GET, POST, PUT, DELETE
```

✅ Good

```http
Allow: GET, HEAD, OPTIONS
```

✅ Good

```http
Allow: CUSTOM-METHOD
```

❌ Bad

```http
Allow: GET, @POST        # invalid character '@' in method token
Allow: GET, , POST       # empty token from double comma
Allow: GET POST          # not comma-separated
Allow:                   # empty header value
```
