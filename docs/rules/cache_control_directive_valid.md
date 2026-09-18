<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Cache Control Directive Valid

## Description

Validate `Cache-Control` directive names and argument formats for common correctness issues. This rule enforces directive-specific semantics such as:

- `max-age`, `s-maxage`, `max-stale`, `min-fresh`, `stale-while-revalidate` and `stale-if-error` must have non-negative integer values (delta-seconds), and RFC 9111 has a sender write that argument in the token form: `max-age="60"` is a well-formed `quoted-string` every recipient reads, and a form the directive's own section says a sender MUST NOT generate.
- `private` and `no-cache` when carrying a field-name-list must provide a comma-separated list of field-names (tokens) either as an unquoted list or inside a quoted-string.
- Unquoted directive values must follow the `token` grammar and quoted values must be valid `quoted-string`s.

This rule complements `cache_control_token_valid` which enforces general token/quoted-string syntax.

## Violations

- [cache_control_argument_quoted_form_forbidden](../violations/cache_control_argument_quoted_form_forbidden.md) — A Cache-Control delta-seconds argument is written in the quoted-string form
- [cache_control_no_cache_argument_empty](../violations/cache_control_no_cache_argument_empty.md) — Cache-Control no-cache is qualified by no field name
- [cache_control_private_argument_empty](../violations/cache_control_private_argument_empty.md) — Cache-Control private is qualified by no field name
- [delta_seconds_character_forbidden](../violations/delta_seconds_character_forbidden.md) — A time in seconds holds an octet DIGIT does not admit
- [list_member_empty](../violations/list_member_empty.md) — List holds an empty element
- [quoted_pair_malformed](../violations/quoted_pair_malformed.md) — Escape is not a quoted-pair
- [quoted_string_control_character_forbidden](../violations/quoted_string_control_character_forbidden.md) — Quoted-string holds a control character
- [quoted_string_delimiter_missing](../violations/quoted_string_delimiter_missing.md) — Quoted-string is missing one of its DQUOTEs
- [quoted_string_quote_escape_missing](../violations/quoted_string_quote_escape_missing.md) — Quoted-string holds an unescaped DQUOTE
- [token_character_forbidden](../violations/token_character_forbidden.md) — Token holds a character outside tchar
- [token_empty](../violations/token_empty.md) — Token is written with no characters in it
- [token_whitespace_or_control_forbidden](../violations/token_whitespace_or_control_forbidden.md) — Token holds whitespace or a control character

## Specifications

- [RFC 9111 §5.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2): Cache-Control directives and general directive syntax
- [RFC 9111 §1.2.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-1.2.1): Imported Rules — `token`, `quoted-string` and `field-name` are RFC 9110's, taken by reference and not restated, which is why a directive's parts report the same defects as any other field written out of them
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The list construct — `1#element => element *( OWS "," OWS element )`, and the sender's MUST NOT against an empty element
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits
- [RFC 9110 §5.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4): `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` — the two delimiters, the class between them, and the backslash escape
- [RFC 9111 §1.2.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-1.2.2): `delta-seconds = 1*DIGIT` — the production every field carrying a time in seconds writes its value in, and the clamp that makes an over-long run of digits conforming
- [RFC 9111 §5.2.2.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.4): no-cache — the unqualified form's prohibition on reuse without forwarding for validation, the argument syntax `#field-name`, the qualified form defined as an argument listing one or more field names, and the Note that caches often handle it as an unqualified no-cache
- [RFC 9111 §5.2.2.7](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.7): private — the unqualified form's prohibition on a shared cache storing the response at all, the argument syntax `#field-name`, the qualified form defined as an argument listing one or more field names, and the Note that caches often handle it as an unqualified private
- [RFC 9111 §5.2.2.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.1): `max-age` response directive — the argument uses the token form, and a sender MUST NOT generate the quoted-string form
- [RFC 9111 §5.2.1.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.1.1): `max-age` request directive — the argument uses the token form, and a sender MUST NOT generate the quoted-string form
- [RFC 9111 §5.2.1.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.1.2): `max-stale` — the argument uses the token form, and a sender MUST NOT generate the quoted-string form
- [RFC 9111 §5.2.1.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.1.3): `min-fresh` — the argument uses the token form, and a sender MUST NOT generate the quoted-string form
- [RFC 9111 §5.2.2.10](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.10): `s-maxage` — the directive is defined for a shared cache, where it overrides the maximum age given by `max-age` or `Expires`; it says nothing to any other kind of cache

## Configuration

```toml
[rules.cache_control_directive_valid]
enabled = true
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
Cache-Control: max-age="60"    # the quoted-string form a sender must not generate
Cache-Control: private=Set Cookie  # space in token
Cache-Control: private="Set Cookie" # quoted content contains space-separated token
```
