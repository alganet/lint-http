<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# parameter_equals_missing

Parameter is written without its '='

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §5.6.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6): Parameters — `parameters = *( OWS ";" OWS [ parameter ] )`, the `name=value` pair inside it with neither half optional, and the bracketing that leaves a trailing `;` conforming

## Configuration

```toml
[violations.parameter_equals_missing]
# Parameter is written without its '='
severity = "warn"
```

## Reported By

- [accept_header_media_type_syntax](../rules/accept_header_media_type_syntax.md)
- [accept_patch_header_valid](../rules/accept_patch_header_valid.md)
- [content_disposition_parameter_valid](../rules/content_disposition_parameter_valid.md)
- [content_type_valid](../rules/content_type_valid.md)
- [expect_header_valid](../rules/expect_header_valid.md)
- [te_header_valid](../rules/te_header_valid.md)
