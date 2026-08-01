<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Content-Type Well-Formed

## Description

Check that a `Content-Type` header — in a request or a response — reads as a valid `media-type`: a non-empty `type` and `subtype`, each a `token`, separated by `/`, followed by well-formed parameters if any are present. A parameter is a `name=value` pair whose name is a `token` and whose value is a `token` or a `quoted-string`; a trailing `;` with nothing after it is fine, since the grammar brackets each parameter as optional.

**More than one `Content-Type` field line is reported.** RFC 9110 §8.3 calls Content-Type a singleton and says duplicated ones are handled by recipients "using the last syntactically valid member of the list, leading to potential interoperability and security issues if different implementations have different error handling behaviors" — so the media type a peer acts on is not the one the message states. Header and trailer sections are counted together.

**A wildcard is reported**, though `*` is a legal `token` and `*/plain` parses. The asterisk belongs to `media-range`, the Accept-side production for naming a *set* of media types; a Content-Type saying `*/*` identifies no representation. This is the rule's judgement rather than a grammar violation.

**Known leniency:** RFC 9110 §5.6.6 forbids whitespace around a parameter's `=`, and this rule trims it, so `charset =utf-8` is accepted. It never causes a false report, only a missed one.

## Specifications

- [RFC 9110 §8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3): Content-Type: `Content-Type = media-type`, and the paragraph naming duplicated field lines as an error whose recipient handling differs between implementations
- [RFC 9110 §8.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1): Media Type: `media-type = type "/" subtype parameters`, both halves `token`, both case-insensitive
- [RFC 9110 §5.6.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6): Parameters: the `name=value` grammar, and the bracketing that makes a trailing `;` conforming. Its prohibition on whitespace around `=` is NOT enforced here
- [RFC 9110 §12.5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.1): Accept: where `*` belongs — `media-range`, which names a set of media types. Cited to explain why a wildcard is reported in Content-Type, which carries a `media-type`
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order: a sender MUST NOT emit multiple field lines for a field with no comma-separated-list alternative

## Configuration

```toml
[rules.message_content_type_well_formed]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Content-Type: text/plain
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

### ❌ Bad (wildcard belongs to Accept, not Content-Type)

```http
Content-Type: */plain
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
