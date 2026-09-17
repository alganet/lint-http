<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_type_charset_missing

A text media type does not say which character encoding it used

## Message

Text-based Content-Type header missing charset parameter.

## Specifications

- [RFC 9110 §8.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.2): What `charset` is for. Note it mandates nothing: no requirement to send the parameter exists, so reporting its absence is this crate's policy

## Configuration

```toml
[violations.content_type_charset_missing]
# A text media type does not say which character encoding it used
severity = "info"
```

## Reported By

- [charset_present](../rules/charset_present.md)
