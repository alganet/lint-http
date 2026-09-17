<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# strict_transport_security_directive_empty

The policy holds a separator with no directive

## Message

Empty directive in Strict-Transport-Security header

## Configuration

```toml
[violations.strict_transport_security_directive_empty]
# The policy holds a separator with no directive
severity = "warn"
```

## Reported By

- [strict_transport_security_valid](../rules/strict_transport_security_valid.md)
