<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# alt_svc_protocol_id_invalid

Alt-Svc protocol-id is not the one spelling this field allows for its ALPN name

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 7838 §3](https://www.rfc-editor.org/rfc/rfc7838.html#section-3): The Alt-Svc HTTP Header Field: `Alt-Svc = clear / 1#alt-value` and the productions under it, the case-sensitive `clear` keyword, the three percent-encoding constraints on a `protocol-id`, and the prose requiring a colon and a port inside the `alt-authority`

## Configuration

```toml
[violations.alt_svc_protocol_id_invalid]
# Alt-Svc protocol-id is not the one spelling this field allows for its ALPN name
severity = "warn"
```

## Reported By

- [alt_svc_header_syntax](../rules/alt_svc_header_syntax.md)
