<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# retry_after_redundant

Retry-After is sent on a status no document pairs it with

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §10.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3): Defines Retry-After generally, with no condition on the status code, then says what it indicates on a 503 and on any 3xx

## Configuration

```toml
[violations.retry_after_redundant]
# Retry-After is sent on a status no document pairs it with
severity = "info"
```

## Reported By

- [retry_after_status_valid](../rules/retry_after_status_valid.md)
