<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# domain_label_character_forbidden

Domain label holds a character outside letters, digits and hyphen

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 1035 §2.3.1](https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.1): Preferred name syntax — labels start with a letter, end with a letter or digit, hold only letters, digits and hyphen, and run to 63 characters

## Configuration

```toml
[violations.domain_label_character_forbidden]
# Domain label holds a character outside letters, digits and hyphen
severity = "warn"
```

## Reported By

- [cookie_domain_valid](../rules/cookie_domain_valid.md)
- [from_header_email_syntax](../rules/from_header_email_syntax.md)
