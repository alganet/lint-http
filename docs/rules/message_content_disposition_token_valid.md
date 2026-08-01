<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Content-Disposition Disposition-Type Token Valid

## Description

Validate that the `Content-Disposition` header's `disposition-type` is present and is a valid `token`. The `disposition-type` is everything before the first `;` (e.g. `attachment` in `attachment; filename="a.txt"`); `inline` and `attachment` are the two named types, and any other value must satisfy `disp-ext-type = token` — no whitespace, controls, or separator characters.

An unrecognized type is **not** an error: RFC 6266 §4.2 says recipients should treat unknown types like `attachment`, so this rule checks the shape of the value and never compares it against a list of known types.

Since the grammar has no comma-separated-list alternative, a message section carries at most one `Content-Disposition` field line (RFC 9110 §5.3). Two lines are reported: recipients that recombine them get `attachment; filename="a", inline` and disagree about where the parameter value ends, which is a real source of filename-handling divergence in downloads.

**Scope:** RFC 6266 defines a *response* header field. This rule also inspects requests, where the field is used in practice by upload APIs but is not defined by RFC 6266. `Content-Disposition` inside multipart body *parts* is a different thing governed by RFC 7578 §4.2; this linter reads message header fields, not parsed body parts.

**Note on `token`:** RFC 6266 §4.1 imports `token` from RFC 2616, which is obsolete. The production is the same set of characters as RFC 9110 §5.6.2's `token = 1*tchar`, which is what this rule enforces.

## Specifications

- [RFC 6266 §4.1](https://www.rfc-editor.org/rfc/rfc6266.html#section-4.1): Grammar: a mandatory `disposition-type` followed by optional `;`-separated parameters, with `disp-ext-type = token`. Whitespace around the separators is implied rather than written
- [RFC 6266 §4.2](https://www.rfc-editor.org/rfc/rfc6266.html#section-4.2): Disposition Type: an unknown type is conforming and has defined handling (treat as `attachment`), which is why this rule validates the value's shape and not its membership in any list
- [RFC 6266 §4](https://www.rfc-editor.org/rfc/rfc6266.html#section-4): Defines Content-Disposition as a *response* header field — the request half of this rule is a deliberate extension beyond the document, since upload APIs do send one
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): `token = 1*tchar` — where the production actually lives now. RFC 6266 §4.1 imports `token` from the obsolete RFC 2616; the character set is unchanged
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order: a sender MUST NOT emit multiple field lines for a field whose definition has no comma-separated-list alternative

## Configuration

```toml
[rules.message_content_disposition_token_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Content-Disposition: attachment; filename="example.txt"
```

```http
Content-Disposition: inline
```

### ❌ Bad

```http
Content-Disposition: ; filename="example.txt"
```

### ✅ Good (an unrecognized type is conforming)

```http
Content-Disposition: preview; filename="a.txt"
```

### ❌ Bad

```http
Content-Disposition: bad@type; filename="a"
```

### ❌ Bad (two field lines in one message — Content-Disposition is a singleton)

```http
HTTP/1.1 200 OK
Content-Disposition: attachment; filename="a.txt"
Content-Disposition: inline
```
