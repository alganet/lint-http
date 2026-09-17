<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# strict_transport_security_empty

The policy is written with nothing in it

## Message

Strict-Transport-Security header must not be empty

## Configuration

```toml
[violations.strict_transport_security_empty]
# The policy is written with nothing in it
severity = "warn"
```

## Reported By

- [strict_transport_security_valid](../rules/strict_transport_security_valid.md)
