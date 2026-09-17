<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# well_known_name_malformed

A well-known name holds a character outside pchar

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 3986 §3.3](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.3): Path — `segment-nz = 1*pchar`, what a `pchar` is, and where the path component ends

## Configuration

```toml
[violations.well_known_name_malformed]
# A well-known name holds a character outside pchar
severity = "info"
```

## Reported By

- [well_known_uri_syntax](../rules/well_known_uri_syntax.md)
