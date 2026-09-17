<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# warning_text_missing

Warning member carries no warn-text

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 7234 §5.5](https://www.rfc-editor.org/rfc/rfc7234.html#section-5.5): The last statement of the `Warning` grammar, and the requirements about warn-codes and warn-dates that go with it. Obsoleted by RFC 9111, which removed the field rather than restating it — so this is where the productions are read from, and RFC 9111 §5.5 is where the field's status is read from

## Configuration

```toml
[violations.warning_text_missing]
# Warning member carries no warn-text
severity = "warn"
```

## Reported By

- [warning_header_syntax](../rules/warning_header_syntax.md)
