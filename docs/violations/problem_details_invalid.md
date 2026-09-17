<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# problem_details_invalid

Content labelled as problem details is a JSON value other than an object

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9457 §3](https://www.rfc-editor.org/rfc/rfc9457.html#section-3): The problem details JSON object and the media type that identifies it; §3.1 and §3.1.1 are where every member is made optional and `type` is given a value for its own absence

## Configuration

```toml
[violations.problem_details_invalid]
# Content labelled as problem details is a JSON value other than an object
severity = "warn"
```

## Reported By

- [problem_details_structure_valid](../rules/problem_details_structure_valid.md)
