<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# upgrade_426_empty

A 426 response names no protocol on its Upgrade field

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §15.5.22](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.22): 426 Upgrade Required — the server refuses the request under the current protocol, and MUST send an `Upgrade` field to indicate the required protocol(s). RFC 9110 §7.8 states the same MUST from the field's side.

## Configuration

```toml
[violations.upgrade_426_empty]
# A 426 response names no protocol on its Upgrade field
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [status_426_upgrade_valid](../rules/status_426_upgrade_valid.md)
