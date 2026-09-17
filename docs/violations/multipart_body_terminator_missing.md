<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# multipart_body_terminator_missing

The body never closes its last part

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 2046 §5.1.1](https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1): Multipart common syntax: `dash-boundary`, `delimiter` and `close-delimiter`, the requirement that a delimiter begin a line, the instruction to compare against the beginning of a candidate line rather than the whole of it, and the ignoring of preamble and epilogue

## Configuration

```toml
[violations.multipart_body_terminator_missing]
# The body never closes its last part
severity = "warn"
```

## Reported By

- [multipart_content_type_and_body_consistent](../rules/multipart_content_type_and_body_consistent.md)
