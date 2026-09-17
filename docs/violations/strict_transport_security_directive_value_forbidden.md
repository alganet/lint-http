<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# strict_transport_security_directive_value_forbidden

A valueless directive is written with a value

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 6797 §6.1.2](https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1.2): The includeSubDomains Directive

## Configuration

```toml
[violations.strict_transport_security_directive_value_forbidden]
# A valueless directive is written with a value
severity = "warn"
```

## Reported By

- [strict_transport_security_valid](../rules/strict_transport_security_valid.md)
