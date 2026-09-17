<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# parameter_value_empty

Parameter is written with no value after its '='

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §5.6.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6): Parameters — `parameters = *( OWS ";" OWS [ parameter ] )`, the `name=value` pair inside it with neither half optional, and the bracketing that leaves a trailing `;` conforming

## Configuration

```toml
[violations.parameter_value_empty]
# Parameter is written with no value after its '='
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [accept_header_media_type_syntax](../rules/accept_header_media_type_syntax.md)
- [accept_patch_header_valid](../rules/accept_patch_header_valid.md)
- [charset_registered](../rules/charset_registered.md)
- [content_disposition_parameter_valid](../rules/content_disposition_parameter_valid.md)
- [content_type_valid](../rules/content_type_valid.md)
- [expect_header_valid](../rules/expect_header_valid.md)
- [form_data_content_disposition_valid](../rules/form_data_content_disposition_valid.md)
- [multipart_boundary_syntax](../rules/multipart_boundary_syntax.md)
- [te_header_valid](../rules/te_header_valid.md)
