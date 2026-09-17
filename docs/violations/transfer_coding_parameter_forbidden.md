<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# transfer_coding_parameter_forbidden

A coding that defines no parameters carries one

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`SHOULD`** binding the sender of the message — advice the specification gives in its own voice and the sender declined — so a finding here reports at `warn` by default.

## Specifications

- [RFC 9112 §7.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.2): The compression transfer codings, and the sentence saying they define no parameters and that a parameter's presence SHOULD be treated as an error

## Configuration

```toml
[violations.transfer_coding_parameter_forbidden]
# A coding that defines no parameters carries one
# SHOULD obliges the sender, so this defaults to warn.
severity = "warn"
```

## Reported By

- [transfer_coding_registered](../rules/transfer_coding_registered.md)
