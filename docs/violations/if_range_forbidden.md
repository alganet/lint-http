<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# if_range_forbidden

If-Range is sent in a request with no Range

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §13.1.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.5): `If-Range`: `entity-tag / HTTP-date`, the first-three-characters DQUOTE test that tells them apart, the MUST NOT on a request with no `Range`, the MUST NOT on a weak entity-tag, and the strong comparison a recipient evaluates the condition with

## Configuration

```toml
[violations.if_range_forbidden]
# If-Range is sent in a request with no Range
severity = "warn"
```

## Reported By

- [conditional_headers_consistent](../rules/conditional_headers_consistent.md)
