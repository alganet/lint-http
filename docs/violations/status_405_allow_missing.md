<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_405_allow_missing

A 405 answers without the Allow field it must generate

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §15.5.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.6): The status code and its MUST — including the clause after "containing", which asks the field to hold the methods the target resource supports and so contradicts a list naming the method this response refuses

## Configuration

```toml
[violations.status_405_allow_missing]
# A 405 answers without the Allow field it must generate
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [status_405_allow_valid](../rules/status_405_allow_valid.md)
