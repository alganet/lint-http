<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# weight_equals_whitespace_forbidden

Whitespace is written beside the weight's '='

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §12.4.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.2): Quality Values — `weight = OWS ";" OWS "q=" qvalue`, the `qvalue` production and its three-digit fraction, the case-insensitive `q` parameter name, and what a weight of zero means

## Configuration

```toml
[violations.weight_equals_whitespace_forbidden]
# Whitespace is written beside the weight's '='
severity = "warn"
```

## Reported By

- [accept_encoding_parameter_valid](../rules/accept_encoding_parameter_valid.md)
- [accept_header_media_type_syntax](../rules/accept_header_media_type_syntax.md)
- [accept_language_weight_valid](../rules/accept_language_weight_valid.md)
- [te_header_valid](../rules/te_header_valid.md)
