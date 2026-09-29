<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Sec Fetch User Value Valid

## Description

Requests that include the `Sec-Fetch-User` request header MUST only include the structured-boolean `true` value (serialized as `?1`) when present. This header is sent by user agents for navigation requests that were triggered by a user activation. Multiple header fields, and any other value, will be flagged as violations.

## Violations

- [field_line_duplicated](../violations/field_line_duplicated.md) — A field is written on more lines than its definition allows
- [sec_fetch_user_value_invalid](../violations/sec_fetch_user_value_invalid.md) — Sec-Fetch-User carries something other than the boolean true
- [sec_fetch_value_empty](../violations/sec_fetch_value_empty.md) — A Sec-Fetch-* field is written with no value on it
- [structured_field_key_malformed](../violations/structured_field_key_malformed.md) — Structured field key is not a key production
- [structured_field_member_empty](../violations/structured_field_member_empty.md) — Structured field writes a comma with no member beside it
- [structured_field_value_malformed](../violations/structured_field_value_malformed.md) — Structured field value is none of the bare item types

## Specifications

- [Fetch Metadata §2.4](https://www.w3.org/TR/fetch-metadata/#sec-fetch-user-header): Fetch Metadata (W3C) — `Sec-Fetch-User`: a boolean, delivered only for navigation requests and only when its value is true
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order — a sender MUST NOT write multiple field lines of one name, in the headers or the trailers, unless at least one alternative of the field's definition allows the lines to be recombined as a comma-separated list
- [RFC 9651 §4.2.2](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.2): Parsing a Dictionary: a member is a key and, optionally, an `=` and a value — a bare key carries the Boolean true rather than being a member without one — and the loop fails on a comma with nothing after it
- [RFC 9651 §4.2.3.3](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.3.3): Parsing a Key: a `key` opens with `lcalpha` or `*` and continues with `lcalpha`, DIGIT, `_`, `-`, `.` or `*` — the production every Dictionary member name and every parameter name is written in, and the one an uppercase letter fails
- [RFC 9651 §4.2.3.1](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.3.1): Parsing a Bare Item — seven types chosen by the value's first character, and a single step for a value that is none of them

## Configuration

```toml
[rules.sec_fetch_user_value_valid]
enabled = true
```

## Examples

### ✅ Good

```http
Sec-Fetch-User: ?1
```

```http
Sec-Fetch-User:  ?1  # whitespace is allowed and trimmed
```

### ❌ Bad

```http
Sec-Fetch-User: true
```

```http
Sec-Fetch-User:
```

```http
Sec-Fetch-User: 1
```
