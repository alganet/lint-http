<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_304_metadata_forbidden

A 304 sends representation metadata beyond the fields it owes

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §15.4.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.5): 304 Not Modified — the fields a 304 MUST send, the SHOULD NOT against any other representation metadata unless it guides cache updates, and the response being terminated by the end of the header section

## Configuration

```toml
[violations.status_304_metadata_forbidden]
# A 304 sends representation metadata beyond the fields it owes
severity = "warn"
```

## Reported By

- [content_encoding_and_type_consistent](../rules/content_encoding_and_type_consistent.md)
