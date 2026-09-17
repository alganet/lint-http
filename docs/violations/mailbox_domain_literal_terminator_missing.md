<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# mailbox_domain_literal_terminator_missing

Mailbox domain-literal is never closed

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 5322 §3.4.1](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.4.1): `addr-spec = local-part "@" domain`, and the `domain-literal` alternative with the `dtext` inside it

## Configuration

```toml
[violations.mailbox_domain_literal_terminator_missing]
# Mailbox domain-literal is never closed
severity = "warn"
```

## Reported By

- [from_header_email_syntax](../rules/from_header_email_syntax.md)
