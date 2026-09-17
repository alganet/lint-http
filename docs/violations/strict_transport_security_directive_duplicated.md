<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# strict_transport_security_directive_duplicated

A directive is written more than once in one policy

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 6797 §6.1](https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1): Strict-Transport-Security header

## Configuration

```toml
[violations.strict_transport_security_directive_duplicated]
# A directive is written more than once in one policy
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [strict_transport_security_valid](../rules/strict_transport_security_valid.md)
