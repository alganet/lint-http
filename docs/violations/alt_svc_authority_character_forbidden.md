<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# alt_svc_authority_character_forbidden

Alt-Svc alt-authority holds an octet no production of it admits

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 7838 §8](https://www.rfc-editor.org/rfc/rfc7838.html#section-8): Internationalization Considerations: an internationalized domain name in this field is written as A-labels, which is what makes an octet at or above %x80 inside an `alt-authority` a defect with a remedy rather than only an octet no production admits

## Configuration

```toml
[violations.alt_svc_authority_character_forbidden]
# Alt-Svc alt-authority holds an octet no production of it admits
severity = "warn"
```

## Reported By

- [alt_svc_header_syntax](../rules/alt_svc_header_syntax.md)
