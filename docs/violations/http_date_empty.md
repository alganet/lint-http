<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# http_date_empty

A date field is written with no timestamp on it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §5.6.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7): Date/Time Formats — `HTTP-date = IMF-fixdate / obs-date`, the recipient's MUST to accept all three, and the sender's MUST to generate only the first

## Configuration

```toml
[violations.http_date_empty]
# A date field is written with no timestamp on it
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [conditional_date_syntax](../rules/conditional_date_syntax.md)
- [date_and_time_headers_consistent](../rules/date_and_time_headers_consistent.md)
- [last_modified_rfc1123_syntax](../rules/last_modified_rfc1123_syntax.md)
- [warning_header_syntax](../rules/warning_header_syntax.md)
