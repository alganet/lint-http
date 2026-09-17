<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# field_response_context_misdirected

A response context field is written in a request

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

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
