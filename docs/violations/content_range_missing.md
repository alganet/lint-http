<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_range_missing

Content-Range is absent from a response whose range it would describe

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §15.3.7.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7.1): 206 Partial Content, single part: the response MUST carry a `Content-Range` describing the enclosed range

## Configuration

```toml
[violations.content_range_missing]
# Content-Range is absent from a response whose range it would describe
severity = "warn"
```

## Reported By

- [range_and_content_range_consistent](../rules/range_and_content_range_consistent.md)
