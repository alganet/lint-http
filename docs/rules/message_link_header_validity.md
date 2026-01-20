<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_link_header_validity

## Description

Validate `Link` header field syntax and common semantics. Ensures each link member contains an angle-bracketed URI (`<...>`), parameter names and values conform to `token`/`quoted-string` rules, and that `rel` values are syntactically valid. When `rel=preload` is used, include an `as` parameter where appropriate (see preload / Early Hints guidance). For `103 Early Hints` responses, `Link` members are commonly used to advertise `preload` hints.

## Specifications

- [RFC 8288](https://www.rfc-editor.org/rfc/rfc8288.html) — Web Linking (Link header field)
- [RFC 8297](https://www.rfc-editor.org/rfc/rfc8297.html) — Early Hints (use of Link for preload hints)
- [W3C Preload spec](https://www.w3.org/TR/preload/) — `rel=preload` and the `as` parameter

## Configuration

```toml
[rules.message_link_header_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Link: <https://example.com/style.css>; rel=preload; as=style
Link: <https://example.com/page2>; rel="next"; title="Next page"
```

### ❌ Bad

```http
Link: https://example.com/style.css; rel=preload     # missing angle brackets
Link: <https://example.com/script.js>; rel=preload    # missing 'as' parameter for preload
Link: <https://example.com/>; bad@=1                  # invalid character in parameter name
```