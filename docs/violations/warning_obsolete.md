<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# warning_obsolete

A message carries a field this specification obsoletes

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9111 §5.5](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.5): Where `Warning` is obsoleted, and where the field's status is read from. The section states no requirement and keeps none of RFC 7234 § 5.5's grammar — it says the field was used, that this specification obsoletes it, and where the information it carried can be found instead

## Configuration

```toml
[violations.warning_obsolete]
# A message carries a field this specification obsoletes
severity = "info"
```

## Reported By

- [warning_header_syntax](../rules/warning_header_syntax.md)
