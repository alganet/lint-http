<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# method_trace_content_forbidden

A TRACE request carries content

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §9.3.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.8): TRACE — the two client `MUST NOT`s, the example naming credentials and cookies, and the `SHOULD` to reflect the message, which is addressed to a recipient no message identifies

## Configuration

```toml
[violations.method_trace_content_forbidden]
# A TRACE request carries content
severity = "warn"
```

## Reported By

- [trace_method_echo](../rules/trace_method_echo.md)
