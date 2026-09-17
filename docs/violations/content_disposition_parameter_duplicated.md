<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_disposition_parameter_duplicated

Content-Disposition names one parameter twice

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 6266 §4.1](https://www.rfc-editor.org/rfc/rfc6266.html#section-4.1): Grammar — `disposition-type *( ";" disposition-parm )`, the `filename`/`filename*` pair, the `ext-token` convention, and the sentence declaring a value with two instances of one parameter name invalid

## Configuration

```toml
[violations.content_disposition_parameter_duplicated]
# Content-Disposition names one parameter twice
severity = "warn"
```

## Reported By

- [content_disposition_parameter_valid](../rules/content_disposition_parameter_valid.md)
