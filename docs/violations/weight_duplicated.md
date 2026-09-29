<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# weight_duplicated

Member carries more than one weight

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Configuration

```toml
[violations.weight_duplicated]
# Member carries more than one weight
severity = "error"
```

## Reported By

- [accept_charset_valid](../rules/accept_charset_valid.md)
- [accept_encoding_parameter_valid](../rules/accept_encoding_parameter_valid.md)
- [accept_header_media_type_syntax](../rules/accept_header_media_type_syntax.md)
- [accept_language_weight_valid](../rules/accept_language_weight_valid.md)
- [digest_header_syntax](../rules/digest_header_syntax.md)
- [te_header_valid](../rules/te_header_valid.md)
