<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_range_empty

Content-Range is empty

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §14.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.4): Content-Range: syntax of `Content-Range` and the semantics for satisfied and unsatisfiable ranges

## Configuration

```toml
[violations.content_range_empty]
# Content-Range is empty
severity = "warn"
```

## Reported By

- [range_and_content_range_consistent](../rules/range_and_content_range_consistent.md)
