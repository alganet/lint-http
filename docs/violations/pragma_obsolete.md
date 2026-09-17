<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# pragma_obsolete

A response carries a field this specification deprecates

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9111 §5.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.4): Pragma — defined for HTTP/1.0 caches so a client could ask for `no-cache`, superseded by `Cache-Control`, deprecated by this specification, and never given a meaning in a response at all

## Configuration

```toml
[violations.pragma_obsolete]
# A response carries a field this specification deprecates
severity = "info"
```

## Reported By

- [cache_control_and_pragma_consistent](../rules/cache_control_and_pragma_consistent.md)
