<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# problem_details_malformed

Content labelled as problem details is not a JSON document

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 8259 §2](https://www.rfc-editor.org/rfc/rfc8259.html#section-2): What a JSON text is — the measure for content that is empty or does not parse; §8.1 adds the UTF-8 requirement the parser also enforces

## Configuration

```toml
[violations.problem_details_malformed]
# Content labelled as problem details is not a JSON document
severity = "warn"
```

## Reported By

- [problem_details_structure_valid](../rules/problem_details_structure_valid.md)
