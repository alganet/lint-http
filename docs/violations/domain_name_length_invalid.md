<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# domain_name_length_invalid

Domain name is longer than 255 octets

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 1035 §2.3.4](https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.4): Size limits — a name is 255 octets or less

## Configuration

```toml
[violations.domain_name_length_invalid]
# Domain name is longer than 255 octets
severity = "warn"
```

## Reported By

- [cookie_domain_valid](../rules/cookie_domain_valid.md)
- [from_header_email_syntax](../rules/from_header_email_syntax.md)
