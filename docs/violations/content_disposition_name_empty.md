<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_disposition_name_empty

A form-data Content-Disposition names an empty form field

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Configuration

```toml
[violations.content_disposition_name_empty]
# A form-data Content-Disposition names an empty form field
severity = "error"
```

## Reported By

- [form_data_content_disposition_valid](../rules/form_data_content_disposition_valid.md)
