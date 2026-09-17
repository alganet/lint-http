<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# max_forwards_empty

Max-Forwards is written with no digits on it

## Message

Max-Forwards is present with no digits; the field is `Max-Forwards = 1*DIGIT`, which requires at least one

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §7.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.2): The field: its grammar (`1*DIGIT`), the methods it works with, and the recipient's permission to ignore it on the others. The section's requirements on intermediaries — check and update the value, do not forward at zero — are stated here and are not measurable from one captured leg

## Configuration

```toml
[violations.max_forwards_empty]
# Max-Forwards is written with no digits on it
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [max_forwards_numeric](../rules/max_forwards_numeric.md)
