<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# mailbox_domain_literal_character_forbidden

Mailbox domain-literal holds a character outside dtext

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 5322 §3.4.1](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.4.1): `addr-spec = local-part "@" domain`, and the `domain-literal` alternative with the `dtext` inside it

## Configuration

```toml
[violations.mailbox_domain_literal_character_forbidden]
# Mailbox domain-literal holds a character outside dtext
severity = "warn"
```

## Reported By

- [from_header_email_syntax](../rules/from_header_email_syntax.md)
