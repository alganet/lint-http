<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# strict_transport_security_max_age_missing

The policy states no max-age

## Message

Strict-Transport-Security header missing required 'max-age' directive

## Specifications

- [RFC 6797 §6.1.1](https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1.1): The max-age Directive

## Configuration

```toml
[violations.strict_transport_security_max_age_missing]
# The policy states no max-age
severity = "warn"
```

## Reported By

- [strict_transport_security_valid](../rules/strict_transport_security_valid.md)
