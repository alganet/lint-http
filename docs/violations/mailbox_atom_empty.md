<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# mailbox_atom_empty

Mailbox atom is empty beside a dot

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 5322 §3.2.3](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.3): `atext`, `atom` and `dot-atom-text` — the printable US-ASCII an atom is made of, and the floor a dot may not leave empty

## Configuration

```toml
[violations.mailbox_atom_empty]
# Mailbox atom is empty beside a dot
severity = "warn"
```

## Reported By

- [from_header_email_syntax](../rules/from_header_email_syntax.md)
