<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# alpn_protocol_name_obsolete

ALPN protocol name identifies a draft of a shipped protocol

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9114 §3.1.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-3.1.1): HTTP Alternative Services — advertising HTTP/3 via Alt-Svc using the "h3" ALPN token

## Configuration

```toml
[violations.alpn_protocol_name_obsolete]
# ALPN protocol name identifies a draft of a shipped protocol
severity = "warn"
```

## Reported By

- [alt_svc_h3_advertisement_valid](../rules/alt_svc_h3_advertisement_valid.md)
