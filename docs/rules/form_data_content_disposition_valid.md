<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Form-Data Content-Disposition Validity

## Description

Ensure that a `form-data` `Content-Disposition` includes a non-empty `name` parameter. RFC 7578 §4.2 requires the parameter and defines its value as the original field name from the form; receiving applications rely on it to associate part data with form fields, so a missing or empty `name` breaks form processing.

**Scope:** RFC 7578 places this requirement on each *part* of a multipart body, but the linter inspects message header fields rather than parsed body parts, so what it checks is a message-level `Content-Disposition`. That position is itself unusual — RFC 6266 defines `inline` and `attachment` for HTTP messages, not `form-data` — so this is a best-effort approximation of the §4.2 check rather than the check itself. Dispositions other than `form-data` are ignored.

An empty `name` value is reported as a defect. The specification requires the parameter and says what it means, but does not literally say "non-empty"; treating an empty field name as broken is this linter's judgement.

**Quoting that never closes is declined, not guessed at.** After a stray `"` no separator can be trusted, so `form-data; p="x; name="a"` is not reported as missing a name — whether that text is a parameter is exactly what the broken quoting makes unknowable. This applies only to the *absence* claim: a `name` the scan did find is still judged.

## Violations

- [content_disposition_name_empty](../violations/content_disposition_name_empty.md) — A form-data Content-Disposition names an empty form field
- [content_disposition_name_missing](../violations/content_disposition_name_missing.md) — A form-data Content-Disposition names no form field
- [parameter_value_empty](../violations/parameter_value_empty.md) — Parameter is written with no value after its '='
- [quoted_pair_malformed](../violations/quoted_pair_malformed.md) — Escape is not a quoted-pair
- [quoted_string_control_character_forbidden](../violations/quoted_string_control_character_forbidden.md) — Quoted-string holds a control character
- [quoted_string_delimiter_missing](../violations/quoted_string_delimiter_missing.md) — Quoted-string is missing one of its DQUOTEs
- [quoted_string_quote_escape_missing](../violations/quoted_string_quote_escape_missing.md) — Quoted-string holds an unescaped DQUOTE

## Specifications

- [RFC 7578 §4.2](https://www.rfc-editor.org/rfc/rfc7578.html#section-4.2): Each multipart/form-data *part* MUST contain a `Content-Disposition` header with disposition-type `form-data` and MUST also contain a `name` parameter — a requirement on parts, which this rule approximates at the message level
- [RFC 6266 §4.1](https://www.rfc-editor.org/rfc/rfc6266.html#section-4.1): The disposition types HTTP messages actually use (`inline`, `attachment`); a message-level `form-data` is outside this grammar, which is why the type gate skips everything else
- [RFC 9110 §5.6.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6): Parameters — `parameters = *( OWS ";" OWS [ parameter ] )`, the `name=value` pair inside it with neither half optional, and the bracketing that leaves a trailing `;` conforming
- [RFC 9110 §5.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4): `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` — the two delimiters, the class between them, and the backslash escape

## Configuration

```toml
[rules.form_data_content_disposition_valid]
enabled = true
```

## Examples

### ✅ Good

```http
Content-Disposition: form-data; name="user"
Content-Disposition: form-data; name=user; filename="photo.png"
```

### ❌ Bad

```http
Content-Disposition: form-data; filename="photo.png"   # missing 'name'
Content-Disposition: form-data; name=   # empty 'name'
```
