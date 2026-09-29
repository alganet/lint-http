<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message ETag Syntax

## Description

Validate that the `ETag` response field contains a single, syntactically valid entity-tag (strong or weak) as defined by RFC 9110. This rule flags a value that is not an `entity-tag`, the special `*` value (which is only meaningful in conditional request headers), and more than one `ETag` field line. The value is read as the octets the sender wrote, so an `obs-text` octet inside the quotes is part of an `opaque-tag` and is not reported.

Both field sections are read. RFC 9110 §8.8.3 lets a sender put `ETag` in the trailer section, for a tag computed while the content streams, so a value written there is measured against the same production, and a tag in each section is two field lines of a singleton, which §5.3 forbids "whether in the headers or trailers".

## Violations

- [etag_character_forbidden](../violations/etag_character_forbidden.md) — Entity-tag holds a character etagc does not admit
- [etag_delimiter_missing](../violations/etag_delimiter_missing.md) — Entity-tag is not quoted
- [etag_weak_indicator_invalid](../violations/etag_weak_indicator_invalid.md) — Weakness indicator is not written W/
- [etag_wildcard_forbidden](../violations/etag_wildcard_forbidden.md) — An ETag carries the wildcard the conditional fields take
- [field_line_duplicated](../violations/field_line_duplicated.md) — A field is written on more lines than its definition allows

## Specifications

- [RFC 9110 §8.8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3): Entity Tags — `entity-tag = [ weak ] opaque-tag`, `weak = %s"W/"` (case-sensitive by the `%s` prefix), `opaque-tag = DQUOTE *etagc DQUOTE`, and `etagc` as VCHAR minus the DQUOTE plus obs-text
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order — a sender MUST NOT write multiple field lines of one name, in the headers or the trailers, unless at least one alternative of the field's definition allows the lines to be recombined as a comma-separated list

## Configuration

```toml
[rules.etag_syntax]
enabled = true
```

## Examples

### ✅ Good (strong ETag)

```http
HTTP/1.1 200 OK
ETag: "33a64df551425fcc55e4d42a148795d9f25f89d4"
```

### ✅ Good (weak ETag)

```http
HTTP/1.1 200 OK
ETag: W/"67ab43"
```

### ❌ Bad (`*` used in response)

```http
HTTP/1.1 200 OK
ETag: *
```

### ❌ Bad (missing quotes)

```http
HTTP/1.1 200 OK
ETag: abc
```

### ❌ Bad (multiple header fields)

```http
HTTP/1.1 200 OK
ETag: "a"
ETag: "b"
```
