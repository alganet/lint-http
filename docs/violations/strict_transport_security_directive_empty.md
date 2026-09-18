<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# strict_transport_security_directive_empty

The policy holds a separator with no directive

## Message

Empty directive in Strict-Transport-Security header

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Configuration

```toml
[violations.strict_transport_security_directive_empty]
# The policy holds a separator with no directive
severity = "info"
```

## Reported By

- [strict_transport_security_valid](../rules/strict_transport_security_valid.md)
