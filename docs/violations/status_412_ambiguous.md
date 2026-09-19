<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_412_ambiguous

A false precondition is answered with success, and nothing shows whether the change was already in place

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §13.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.1): `If-Match`: an origin server MUST NOT perform the method when the condition is false, MAY answer 412, and MAY answer 2xx where the state-changing request appears to have already been applied
- [RFC 9110 §13.1.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.4): `If-Unmodified-Since`: the recipient MUST ignore it when an `If-Match` is present, and when the value is no HTTP-date

## Configuration

```toml
[violations.status_412_ambiguous]
# A false precondition is answered with success, and nothing shows whether the change was already in place
severity = "warn"
```

## Reported By

- [conditional_request_handling](../rules/conditional_request_handling.md)
