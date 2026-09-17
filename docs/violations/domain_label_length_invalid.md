<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# domain_label_length_invalid

Domain label is longer than 63 characters

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 1035 §2.3.1](https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.1): Preferred name syntax — labels start with a letter, end with a letter or digit, hold only letters, digits and hyphen, and run to 63 characters

## Configuration

```toml
[violations.domain_label_length_invalid]
# Domain label is longer than 63 characters
severity = "warn"
```

## Reported By

- [cookie_domain_valid](../rules/cookie_domain_valid.md)
- [from_header_email_syntax](../rules/from_header_email_syntax.md)
