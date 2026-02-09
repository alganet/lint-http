<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Form-Data Content-Disposition Validity

## Description

Ensure that `Content-Disposition` headers for `form-data` parts include a `name` parameter (non-empty). When a multipart part uses `form-data` disposition, RFC 7578 §4.2 requires a `name` parameter whose value is the field name from the form.

Multipart `form-data` parts identify the form field that produced the part using a `Content-Disposition: form-data; name="..."` header. Receiving applications rely on the `name` parameter to associate part data with form fields; missing or empty `name` parameters break form processing and interoperability.

This rule flags `Content-Disposition` header fields whose disposition-type is `form-data` but that do not include a `name` parameter or include an empty `name` value.

## Specifications

- [RFC 7578 §4.2](https://www.rfc-editor.org/rfc/rfc7578.html#section-4.2) — Each multipart/form-data part MUST contain a `Content-Disposition` header with disposition-type `form-data` and MUST also contain an additional parameter of `name`.

## Configuration

Enable the rule in TOML:

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
