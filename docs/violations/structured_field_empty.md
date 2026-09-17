<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# structured_field_empty

Structured field is written with nothing on it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9651 §3.2](https://www.rfc-editor.org/rfc/rfc9651.html#section-3.2): Dictionaries — keys cannot contain uppercase, unknown members are ignored by recipients, members may be spread across field lines, and an empty Dictionary is spelled by leaving the field out

## Configuration

```toml
[violations.structured_field_empty]
# Structured field is written with nothing on it
severity = "info"
```

## Reported By

- [permissions_policy_directives_valid](../rules/permissions_policy_directives_valid.md)
