<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# method_options_capabilities_missing

A successful OPTIONS answers with none of the capabilities it was asked for

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`SHOULD`** binding the sender of the message — advice the specification gives in its own voice and the sender declined — so a finding here reports at `warn` by default.

## Specifications

- [RFC 9110 §9.3.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.7): OPTIONS — the client `MUST` about `Content-Type`, and the `SHOULD` to advertise, which names a class ending "including potential extensions not defined by this specification" rather than a field

## Configuration

```toml
[violations.method_options_capabilities_missing]
# A successful OPTIONS answers with none of the capabilities it was asked for
# SHOULD obliges the sender, so this defaults to warn.
severity = "warn"
```

## Reported By

- [options_method_capabilities](../rules/options_method_capabilities.md)
