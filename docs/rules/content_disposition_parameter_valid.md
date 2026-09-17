<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Content-Disposition Parameter Validity

## Description

`Content-Disposition` parameters provide metadata about how to handle a payload (for example, the suggested filename). Malformed parameters can break user agents or enable confusing behavior. This rule validates parameter name syntax and performs focused checks on common parameters:

- `filename` — must be a `token` or a valid `quoted-string`.
- `filename*` — must be a valid RFC 8187 `ext-value` (e.g., `UTF-8''%e2%82%ac%20rates`).
- `size` — must be a numeric value (digits only), optionally quoted.

When a parameter value is syntactically invalid, the rule raises a `warn`-level violation by default.

**Scope:** this rule covers `disposition-parm` and nothing above it. An empty field value, a missing `disposition-type` and more than one `Content-Disposition` field line are all reported by `content_disposition_token_valid`, which owns that part of the grammar. Those inputs leave no parameters to inspect, so this rule stays silent on them rather than emitting a second, identical finding. A value carrying octets outside visible US-ASCII is not decoded here either, and no rule reports it: RFC 6266 §4.3 makes a `filename` exactly as wide as ISO-8859-1, so such an octet is one of its characters and the `quoted-string` carrying it admits it as `obs-text`.

## Violations

- [content_disposition_parameter_duplicated](../violations/content_disposition_parameter_duplicated.md) — Content-Disposition names one parameter twice
- [content_disposition_size_invalid](../violations/content_disposition_size_invalid.md) — A Content-Disposition size parameter is not a number
- [ext_value_malformed](../violations/ext_value_malformed.md) — An extended parameter value is no ext-value
- [parameter_equals_missing](../violations/parameter_equals_missing.md) — Parameter is written without its '='
- [parameter_value_empty](../violations/parameter_value_empty.md) — Parameter is written with no value after its '='
- [quoted_pair_malformed](../violations/quoted_pair_malformed.md) — Escape is not a quoted-pair
- [quoted_string_control_character_forbidden](../violations/quoted_string_control_character_forbidden.md) — Quoted-string holds a control character
- [quoted_string_delimiter_missing](../violations/quoted_string_delimiter_missing.md) — Quoted-string is missing one of its DQUOTEs
- [quoted_string_quote_escape_missing](../violations/quoted_string_quote_escape_missing.md) — Quoted-string holds an unescaped DQUOTE
- [token_character_forbidden](../violations/token_character_forbidden.md) — Token holds a character outside tchar
- [token_empty](../violations/token_empty.md) — Token is written with no characters in it
- [token_whitespace_or_control_forbidden](../violations/token_whitespace_or_control_forbidden.md) — Token holds whitespace or a control character

## Specifications

- [RFC 6266 §4](https://www.rfc-editor.org/rfc/rfc6266.html#section-4): Use of `Content-Disposition` in HTTP (parameters, `filename`, `filename*`, `size` notes)
- [RFC 6266 §4.1](https://www.rfc-editor.org/rfc/rfc6266.html#section-4.1): Grammar — `disposition-type *( ";" disposition-parm )`, the `filename`/`filename*` pair, the `ext-token` convention, and the sentence declaring a value with two instances of one parameter name invalid
- [RFC 8187 §3.2.1](https://www.rfc-editor.org/rfc/rfc8187.html#section-3.2.1): `ext-value = charset "'" [ language ] "'" value-chars` — the charset that may not be empty, the language that may be, and the `value-chars` made of `pct-encoded` and `attr-char`. Obsoletes RFC 5987, which older references named; the production is unchanged
- [RFC 9110 §5.6.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6): Parameters — `parameters = *( OWS ";" OWS [ parameter ] )`, the `name=value` pair inside it with neither half optional, and the bracketing that leaves a trailing `;` conforming
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits
- [RFC 9110 §5.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4): `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` — the two delimiters, the class between them, and the backslash escape

## Configuration

```toml
[rules.content_disposition_parameter_valid]
enabled = true
```

## Examples

### ✅ Good

```http
Content-Disposition: attachment; filename="example.txt"
Content-Disposition: attachment; filename*=UTF-8''%e2%82%ac%20rates
Content-Disposition: attachment; filename=example.txt; size=12345
```

### ❌ Bad

```http
Content-Disposition: attachment; filename=unclosed
Content-Disposition: attachment; filename*=UTF-8'%e2%82%ac   ;  # missing second quote
Content-Disposition: attachment; size=12a
Content-Disposition: attachment; filename=foo; filename=bar  # duplicate parameter name
```
