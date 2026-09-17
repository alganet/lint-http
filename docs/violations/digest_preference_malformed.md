<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# digest_preference_malformed

Want-Digest preference is not an Integer

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9530 §4](https://www.rfc-editor.org/rfc/rfc9530.html#section-4): `Want-Content-Digest` / `Want-Repr-Digest`: a Dictionary whose values are Integers in the range 0 to 10 inclusive

## Configuration

```toml
[violations.digest_preference_malformed]
# Want-Digest preference is not an Integer
severity = "warn"
```

## Reported By

- [digest_header_syntax](../rules/digest_header_syntax.md)
