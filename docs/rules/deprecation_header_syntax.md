<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Deprecation Header Syntax

## Description

The `Deprecation` response header signals that a resource is deprecated. RFC 9745 defines the header as a Structured Field `Date` item (a numeric timestamp expressed as `@<seconds>`). This rule validates the canonical structured form and flags legacy or invalid forms (literal `true`, HTTP-date, non-numeric `@` values) with helpful messages.

## Specifications

- [RFC 9745 §2.1](https://www.rfc-editor.org/rfc/rfc9745.html#section-2.1): Syntax: `Deprecation` is an Item Structured Header Field whose value MUST be a `Date`
- [RFC 9651 §3.3.7](https://www.rfc-editor.org/rfc/rfc9651.html#section-3.3.7): Structured Field `Date` item syntax (leading `@`)
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order — a sender MUST NOT write multiple field lines of one name, in the headers or the trailers, unless at least one alternative of the field's definition allows the lines to be recombined as a comma-separated list

## Configuration

```toml
[rules.deprecation_header_syntax]
enabled = true
severity = "warn"
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
