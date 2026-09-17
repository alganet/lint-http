<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# preference_applied_value_empty

A Preference-Applied member writes an = with no word after it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 7240 §3](https://www.rfc-editor.org/rfc/rfc7240.html#section-3): `Preference-Applied` — the field's definition, its grammar, and the sentence saying it is the `Prefer` grammar without parameters

## Configuration

```toml
[violations.preference_applied_value_empty]
# A Preference-Applied member writes an = with no word after it
severity = "warn"
```

## Reported By

- [preference_applied_header_valid](../rules/preference_applied_header_valid.md)
