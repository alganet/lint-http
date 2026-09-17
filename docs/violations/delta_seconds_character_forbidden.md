<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# delta_seconds_character_forbidden

A time in seconds holds an octet DIGIT does not admit

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9111 §1.2.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-1.2.2): `delta-seconds = 1*DIGIT` — the production every field carrying a time in seconds writes its value in, and the clamp that makes an over-long run of digits conforming

## Configuration

```toml
[violations.delta_seconds_character_forbidden]
# A time in seconds holds an octet DIGIT does not admit
severity = "warn"
```

## Reported By

- [age_header_numeric](../rules/age_header_numeric.md)
- [alt_svc_h3_advertisement_valid](../rules/alt_svc_h3_advertisement_valid.md)
- [cache_control_directive_valid](../rules/cache_control_directive_valid.md)
- [keep_alive_header_valid](../rules/keep_alive_header_valid.md)
- [strict_transport_security_valid](../rules/strict_transport_security_valid.md)
