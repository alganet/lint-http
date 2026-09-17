<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# preference_applied_conflicting

A Preference-Applied reports a value the request did not ask for

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 7240 §2](https://www.rfc-editor.org/rfc/rfc7240.html#section-2): `Prefer` — the grammar, the equivalence of several field lines with one, the equivalence of an empty value with no value, the case rules for names and values, the SHOULD NOT against repeating a token, and the server's MUST to ignore a preference it does not recognize

## Configuration

```toml
[violations.preference_applied_conflicting]
# A Preference-Applied reports a value the request did not ask for
severity = "warn"
```

## Reported By

- [preference_applied_header_valid](../rules/preference_applied_header_valid.md)
