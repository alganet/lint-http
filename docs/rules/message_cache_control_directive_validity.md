<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_cache_control_directive_validity

## Description

Validate `Cache-Control` directive names and argument formats for common correctness issues. This rule enforces directive-specific semantics such as:

- `max-age` and `s-maxage` must have non-negative integer values (delta-seconds).
- `private` and `no-cache` when carrying a field-name-list must provide a comma-separated list of field-names (tokens) either as an unquoted list or inside a quoted-string.
- Unquoted directive values must follow the `token` grammar and quoted values must be valid `quoted-string`s.

This rule complements `message_cache_control_token_valid` which enforces general token/quoted-string syntax.

## Specifications

- [RFC 9110 §5.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.2) — Cache-Control directives and general directive syntax

## Configuration

```toml
[rules.message_cache_control_directive_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Cache-Control: max-age=3600
Cache-Control: s-maxage=0, public
Cache-Control: private="Set-Cookie, X-Foo"
Cache-Control: private=Foo,bar
```

### ❌ Bad

```http
Cache-Control: max-age=abc     # non-numeric max-age
Cache-Control: max-age=-1      # negative values not allowed
Cache-Control: s-maxage=1.5    # fractional values invalid
Cache-Control: private=Set Cookie  # space in token
Cache-Control: private="Set Cookie" # quoted content contains space-separated token
```