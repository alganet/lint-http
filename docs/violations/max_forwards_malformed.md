<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# max_forwards_malformed

Max-Forwards holds something that is not a digit

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §7.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.2): The field: its grammar (`1*DIGIT`), the methods it works with, and the recipient's permission to ignore it on the others. The section's requirements on intermediaries — check and update the value, do not forward at zero — are stated here and are not measurable from one captured leg

## Configuration

```toml
[violations.max_forwards_malformed]
# Max-Forwards holds something that is not a digit
severity = "warn"
```

## Reported By

- [max_forwards_numeric](../rules/max_forwards_numeric.md)
