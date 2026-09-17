<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# field_name_unregistered

Field name is not one the deployment expects

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.1): Field Names (case-insensitive, and registration is an "ought to"; the same paragraph makes a proxy forward what it does not recognize)

## Configuration

```toml
[violations.field_name_unregistered]
# Field name is not one the deployment expects
severity = "warn"
```

## Reported By

- [extension_headers_registered](../rules/extension_headers_registered.md)
