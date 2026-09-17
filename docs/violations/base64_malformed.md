<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# base64_malformed

Value is not a base64 encoding

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 4648 §3.3](https://www.rfc-editor.org/rfc/rfc4648.html#section-3.3): Interpretation of non-alphabet characters — a MUST to reject data outside the base alphabet, unless the referring specification says otherwise

## Configuration

```toml
[violations.base64_malformed]
# Value is not a base64 encoding
severity = "warn"
```

## Reported By

- [basic_auth_base64_valid](../rules/basic_auth_base64_valid.md)
- [digest_header_syntax](../rules/digest_header_syntax.md)
