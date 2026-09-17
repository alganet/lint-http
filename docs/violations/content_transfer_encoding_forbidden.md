<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_transfer_encoding_forbidden

A MIME field HTTP does not use survived into an HTTP message

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9112 §B.5](https://www.rfc-editor.org/rfc/rfc9112.html#appendix-B.5): Why the field is reported at all: HTTP does not use Content-Transfer-Encoding, and gateways from MIME-compliant protocols must remove it

## Configuration

```toml
[violations.content_transfer_encoding_forbidden]
# A MIME field HTTP does not use survived into an HTTP message
severity = "warn"
```

## Reported By

- [content_transfer_encoding_valid](../rules/content_transfer_encoding_valid.md)
