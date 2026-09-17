<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_1xx_forbidden

An interim response answers a client whose version has none

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §15.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2): Informational 1xx — the class is interim, such a response is terminated by the end of the header section and cannot contain content or trailers, and a server must not send one to an HTTP/1.0 client, which defined no 1xx status codes

## Configuration

```toml
[violations.status_1xx_forbidden]
# An interim response answers a client whose version has none
severity = "warn"
```

## Reported By

- [status_103_early_hints_before_final](../rules/status_103_early_hints_before_final.md)
