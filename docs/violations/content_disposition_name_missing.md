<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_disposition_name_missing

A form-data Content-Disposition names no form field

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 7578 §4.2](https://www.rfc-editor.org/rfc/rfc7578.html#section-4.2): Each multipart/form-data *part* MUST contain a `Content-Disposition` header with disposition-type `form-data` and MUST also contain a `name` parameter — a requirement on parts, which this rule approximates at the message level

## Configuration

```toml
[violations.content_disposition_name_missing]
# A form-data Content-Disposition names no form field
severity = "warn"
```

## Reported By

- [form_data_content_disposition_valid](../rules/form_data_content_disposition_valid.md)
