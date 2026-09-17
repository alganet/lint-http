<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# strict_transport_security_max_age_missing

The policy states no max-age

## Message

Strict-Transport-Security header missing required 'max-age' directive

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 6797 §6.1.1](https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1.1): The max-age Directive

## Configuration

```toml
[violations.strict_transport_security_max_age_missing]
# The policy states no max-age
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [strict_transport_security_valid](../rules/strict_transport_security_valid.md)
