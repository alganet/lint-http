<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# field_response_context_misdirected

A response context field is written in a request

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §10.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2): Response Context Fields — the four whose subjects are the server, the target resource and related resources. No sentence in either section forbids the misdirection, which is why both entries are advice

## Configuration

```toml
[violations.field_response_context_misdirected]
# A response context field is written in a request
severity = "info"
```

## Reported By

- [context_fields_direction](../rules/context_fields_direction.md)
