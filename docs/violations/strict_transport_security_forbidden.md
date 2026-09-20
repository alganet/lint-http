<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# strict_transport_security_forbidden

A policy is sent on a response the transport never secured

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 6797 §7.2](https://www.rfc-editor.org/rfc/rfc6797.html#section-7.2): HTTP Request Type

## Configuration

```toml
[violations.strict_transport_security_forbidden]
# A policy is sent on a response the transport never secured
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [strict_transport_security_valid](../rules/strict_transport_security_valid.md)
