<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# connection_option_forbidden

A connection-option names a field the whole chain must read

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §7.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1): The field itself: its grammar, the case-insensitivity of its options, the note that an option need not correspond to a field present in the message, and the MUST NOT on naming a field that is intended for all recipients of the content

## Configuration

```toml
[violations.connection_option_forbidden]
# A connection-option names a field the whole chain must read
severity = "warn"
```

## Reported By

- [connection_header_tokens_valid](../rules/connection_header_tokens_valid.md)
