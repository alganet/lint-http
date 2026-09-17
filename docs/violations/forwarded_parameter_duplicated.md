<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# forwarded_parameter_duplicated

Forwarded element names one parameter more than once

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 7239 §4](https://www.rfc-editor.org/rfc/rfc7239.html#section-4): The field's grammar, the case-insensitivity of parameter names, the MUST NOT on naming a parameter twice in one element, and the sentence restricting the field to requests

## Configuration

```toml
[violations.forwarded_parameter_duplicated]
# Forwarded element names one parameter more than once
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [forwarded_header_valid](../rules/forwarded_header_valid.md)
