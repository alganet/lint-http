<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# http_date_obsolete

Timestamp is written in an obsolete date format

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §5.6.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7): Date/Time Formats — `HTTP-date = IMF-fixdate / obs-date`, the recipient's MUST to accept all three, and the sender's MUST to generate only the first

## Configuration

```toml
[violations.http_date_obsolete]
# Timestamp is written in an obsolete date format
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [conditional_date_syntax](../rules/conditional_date_syntax.md)
- [conditional_headers_consistent](../rules/conditional_headers_consistent.md)
- [expires_date_syntax](../rules/expires_date_syntax.md)
- [last_modified_rfc1123_syntax](../rules/last_modified_rfc1123_syntax.md)
- [warning_header_syntax](../rules/warning_header_syntax.md)
