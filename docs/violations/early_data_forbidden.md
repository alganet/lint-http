<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# early_data_forbidden

Early-Data appears where the section forbids it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 8470 §5.1](https://www.rfc-editor.org/rfc/rfc8470.html#section-5.1): The Early-Data Header Field — one valid value, one instance added by an intermediary only where none is present, invalid or repeated instances read as a single "1", and the prohibitions on a Connection field, a response and a request trailer section

## Configuration

```toml
[violations.early_data_forbidden]
# Early-Data appears where the section forbids it
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [early_data_header_safe_method](../rules/early_data_header_safe_method.md)
