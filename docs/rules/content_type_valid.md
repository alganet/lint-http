<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Content-Type Well-Formed

## Description

Check that a `Content-Type` header — in a request or a response — reads as a valid `media-type`: a non-empty `type` and `subtype`, each a `token`, separated by `/`, followed by well-formed parameters if any are present. A parameter is a `name=value` pair whose name is a `token` and whose value is a `token` or a `quoted-string`; a trailing `;` with nothing after it is fine, since the grammar brackets each parameter as optional.

**More than one `Content-Type` field line is reported.** RFC 9110 §8.3 calls Content-Type a singleton and says duplicated ones are handled by recipients "using the last syntactically valid member of the list, leading to potential interoperability and security issues if different implementations have different error handling behaviors" — so the media type a peer acts on is not the one the message states. Header and trailer sections are counted together.

**A wildcard is reported**, though `*` is a legal `token` and `text/*` parses as a `media-type`. The asterisk is defined in §12.5.1 as what groups media types into *ranges* — `media-range`, which Accept takes and Content-Type does not — so a Content-Type carrying one names a set where a single media type is expected. This is the rule's judgement, not a grammar violation. (`*/plain` is rejected too, though it is not a valid `media-range` either: `media-range` allows `*/*` and `type/*`, never a wildcard type with a concrete subtype.)

**Precedence:** when more than one field line is present, the duplication is reported and the individual values are not validated. A section yields one finding, and which value applies comes before whether a value is well formed. The precedence is within a section: a defective request `Content-Type` and a defective response `Content-Type` are two peers' defects and are both reported.

**Whitespace beside a parameter's `=` is reported.** RFC 9110 §5.6.6 forbids it in the production and again in prose — not even the "bad" whitespace HTTP tolerates elsewhere — so `charset =utf-8` derives from nothing. This rule used to trim it and publish the leniency here; the other two ways a `parameter` fails to derive were already reported from the same reader, and enforcing two thirds of one sentence made a claim about the third that nothing backed.

## Violations

- [field_line_duplicated](../violations/field_line_duplicated.md) — A field is written on more lines than its definition allows
- [media_type_empty](../violations/media_type_empty.md) — Media type is written with nothing in it
- [media_type_malformed](../violations/media_type_malformed.md) — Media type is not a type/subtype pair
- [media_type_wildcard_forbidden](../violations/media_type_wildcard_forbidden.md) — A media range is written where one media type belongs
- [parameter_equals_missing](../violations/parameter_equals_missing.md) — Parameter is written without its '='
- [parameter_equals_whitespace_forbidden](../violations/parameter_equals_whitespace_forbidden.md) — Parameter writes whitespace beside its '='
- [parameter_value_empty](../violations/parameter_value_empty.md) — Parameter is written with no value after its '='
- [quoted_pair_malformed](../violations/quoted_pair_malformed.md) — Escape is not a quoted-pair
- [quoted_string_control_character_forbidden](../violations/quoted_string_control_character_forbidden.md) — Quoted-string holds a control character
- [quoted_string_delimiter_missing](../violations/quoted_string_delimiter_missing.md) — Quoted-string is missing one of its DQUOTEs
- [quoted_string_quote_escape_missing](../violations/quoted_string_quote_escape_missing.md) — Quoted-string holds an unescaped DQUOTE
- [token_character_forbidden](../violations/token_character_forbidden.md) — Token holds a character outside tchar
- [token_empty](../violations/token_empty.md) — Token is written with no characters in it
- [token_whitespace_or_control_forbidden](../violations/token_whitespace_or_control_forbidden.md) — Token holds whitespace or a control character

## Specifications

- [RFC 9110 §8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3): Content-Type: `Content-Type = media-type`, and the paragraph naming duplicated field lines as an error whose recipient handling differs between implementations
- [RFC 9110 §8.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1): Media Type: `media-type = type "/" subtype parameters`, both halves `token` and both case-insensitive, and the "ought to be registered with IANA" guidance — guidance rather than a requirement, and not something this crate verifies
- [RFC 9110 §5.6.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6): Parameters — `parameters = *( OWS ";" OWS [ parameter ] )`, the `name=value` pair inside it with neither half optional, and the bracketing that leaves a trailing `;` conforming
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits
- [RFC 9110 §5.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4): `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` — the two delimiters, the class between them, and the backslash escape
- [RFC 9110 §12.5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.1): Accept and its `media-range` — where the asterisk groups media types into ranges, which is the reason it names nothing in a Content-Type
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order — a sender MUST NOT write multiple field lines of one name, in the headers or the trailers, unless at least one alternative of the field's definition allows the lines to be recombined as a comma-separated list

## Configuration

```toml
[rules.content_type_valid]
enabled = true
```

## Examples

### ✅ Good

```http
Content-Type: application/octet-stream
```

### ✅ Good (token parameter)

```http
Content-Type: application/json; charset=utf-8
```

### ✅ Good (quoted-string parameter, and a trailing `;` is conforming)

```http
Content-Type: image/vnd.example+json; foo="bar"; charset=utf-8;
```

### ❌ Bad (no subtype)

```http
Content-Type: text
```

### ❌ Bad (empty subtype)

```http
Content-Type: text/
```

### ❌ Bad (a media-range names a set of types; Accept takes those, Content-Type does not)

```http
Content-Type: text/*
```

### ❌ Bad (parameter without a value)

```http
Content-Type: text/plain; badparam
```

### ❌ Bad (unterminated quoted-string)

```http
Content-Type: text/plain; charset="unclosed
```

### ❌ Bad (two field lines in one message — Content-Type is a singleton)

```http
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Type: application/json
```
