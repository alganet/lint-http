<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_type_charset_missing

A text media type does not say which character encoding it used

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

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
