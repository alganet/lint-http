<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Deprecation Header Syntax

## Description

The `Deprecation` response header signals that a resource is deprecated. RFC 9745 defines the header as a Structured Field `Date` item (a numeric timestamp expressed as `@<seconds>`). This rule validates the canonical structured form and flags legacy or invalid forms (literal `true`, HTTP-date, non-numeric `@` values) with helpful messages.

## Violations

- [deprecation_malformed](../violations/deprecation_malformed.md) — A Deprecation is not a Structured Field Date
- [field_line_duplicated](../violations/field_line_duplicated.md) — A field is written on more lines than its definition allows
- [structured_field_key_malformed](../violations/structured_field_key_malformed.md) — Structured field key is not a key production
- [structured_field_member_empty](../violations/structured_field_member_empty.md) — Structured field writes a comma with no member beside it
- [structured_field_value_malformed](../violations/structured_field_value_malformed.md) — Structured field value is none of the bare item types

## Specifications

- [RFC 9745 §2.1](https://www.rfc-editor.org/rfc/rfc9745.html#section-2.1): Syntax: `Deprecation` is an Item Structured Header Field whose value MUST be a `Date`
- [RFC 9651 §3.3.7](https://www.rfc-editor.org/rfc/rfc9651.html#section-3.3.7): Structured Field `Date` item syntax (leading `@`)
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order — a sender MUST NOT write multiple field lines of one name, in the headers or the trailers, unless at least one alternative of the field's definition allows the lines to be recombined as a comma-separated list
- [RFC 9651 §4.2.2](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.2): Parsing a Dictionary: a member is a key and, optionally, an `=` and a value — a bare key carries the Boolean true rather than being a member without one — and the loop fails on a comma with nothing after it
- [RFC 9651 §4.2.3.3](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.3.3): Parsing a Key: a `key` opens with `lcalpha` or `*` and continues with `lcalpha`, DIGIT, `_`, `-`, `.` or `*` — the production every Dictionary member name and every parameter name is written in, and the one an uppercase letter fails
- [RFC 9651 §4.2.3.1](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.3.1): Parsing a Bare Item — seven types chosen by the value's first character, and a single step for a value that is none of them

## Configuration

```toml
[rules.deprecation_header_syntax]
enabled = true
```

## Examples

### ✅ Good

```http
Deprecation: @1688169599
Deprecation:   @0
```

### ❌ Bad

```http
Deprecation: true
Deprecation: Wed, 11 Nov 2015 07:28:00 GMT
Deprecation: @
Deprecation: @-1
Deprecation: @abc
```
