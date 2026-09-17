<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_disposition_name_missing

A form-data Content-Disposition names no form field

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

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
