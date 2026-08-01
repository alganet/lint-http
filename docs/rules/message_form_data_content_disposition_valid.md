<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Form-Data Content-Disposition Validity

## Description

Ensure that a `form-data` `Content-Disposition` includes a non-empty `name` parameter. RFC 7578 §4.2 requires the parameter and defines its value as the original field name from the form; receiving applications rely on it to associate part data with form fields, so a missing or empty `name` breaks form processing.

**Scope:** RFC 7578 places this requirement on each *part* of a multipart body, but the linter inspects message header fields rather than parsed body parts, so what it checks is a message-level `Content-Disposition`. That position is itself unusual — RFC 6266 defines `inline` and `attachment` for HTTP messages, not `form-data` — so this is a best-effort approximation of the §4.2 check rather than the check itself. Dispositions other than `form-data` are ignored.

An empty `name` value is reported as a defect. The specification requires the parameter and says what it means, but does not literally say "non-empty"; treating an empty field name as broken is this linter's judgement.

## Specifications

- [RFC 7578 §4.2](https://www.rfc-editor.org/rfc/rfc7578.html#section-4.2): Each multipart/form-data *part* MUST contain a `Content-Disposition` header with disposition-type `form-data` and MUST also contain a `name` parameter — a requirement on parts, which this rule approximates at the message level
- [RFC 6266 §4.1](https://www.rfc-editor.org/rfc/rfc6266.html#section-4.1): The disposition types HTTP messages actually use (`inline`, `attachment`); a message-level `form-data` is outside this grammar, which is why the type gate skips everything else

## Configuration

```toml
[rules.message_form_data_content_disposition_valid]
enabled = true
severity = "warn"
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
