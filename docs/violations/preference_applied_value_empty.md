<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# preference_applied_value_empty

A Preference-Applied member writes an = with no word after it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 7240 §3](https://www.rfc-editor.org/rfc/rfc7240.html#section-3): `Preference-Applied` — the field's definition, its grammar, and the sentence saying it is the `Prefer` grammar without parameters

## Configuration

```toml
[violations.preference_applied_value_empty]
# A Preference-Applied member writes an = with no word after it
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [preference_applied_header_valid](../rules/preference_applied_header_valid.md)
