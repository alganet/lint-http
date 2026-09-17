<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# transfer_coding_unregistered

Transfer coding is not one the deployment recognises

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9112 §7](https://www.rfc-editor.org/rfc/rfc9112.html#section-7): Transfer Codings — names are case-insensitive and ought to be registered; §7.3 puts registration behind IETF Review, which is why an unrecognised name is a configuration question

## Configuration

```toml
[violations.transfer_coding_unregistered]
# Transfer coding is not one the deployment recognises
severity = "warn"
```

## Reported By

- [transfer_coding_registered](../rules/transfer_coding_registered.md)
