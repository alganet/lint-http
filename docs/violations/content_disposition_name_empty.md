<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_disposition_name_empty

A form-data Content-Disposition names an empty form field

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Configuration

```toml
[violations.content_disposition_name_empty]
# A form-data Content-Disposition names an empty form field
severity = "warn"
```

## Reported By

- [form_data_content_disposition_valid](../rules/form_data_content_disposition_valid.md)
