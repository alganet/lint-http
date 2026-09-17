<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# strict_transport_security_directive_duplicated

A directive is written more than once in one policy

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 6797 §6.1](https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1): Strict-Transport-Security header

## Configuration

```toml
[violations.strict_transport_security_directive_duplicated]
# A directive is written more than once in one policy
severity = "warn"
```

## Reported By

- [strict_transport_security_valid](../rules/strict_transport_security_valid.md)
