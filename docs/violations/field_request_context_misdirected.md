<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# field_request_context_misdirected

A request context field is written in a response

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §10.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1): Request Context Fields — the five fields whose subjects are the user, user agent and resource behind a request; the section split the direction is read from

## Configuration

```toml
[violations.field_request_context_misdirected]
# A request context field is written in a response
severity = "info"
```

## Reported By

- [context_fields_direction](../rules/context_fields_direction.md)
- [te_header_valid](../rules/te_header_valid.md)
