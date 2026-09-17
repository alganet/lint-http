<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_range_numeral_malformed

Content-Range numeral is not 1*DIGIT

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §14.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.4): Content-Range: syntax of `Content-Range` and the semantics for satisfied and unsatisfiable ranges

## Configuration

```toml
[violations.content_range_numeral_malformed]
# Content-Range numeral is not 1*DIGIT
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [range_and_content_range_consistent](../rules/range_and_content_range_consistent.md)
