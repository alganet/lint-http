<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# refresh_value_malformed

A Refresh value is neither of the two forms

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [HTML Semantics §4.2.5.3](https://html.spec.whatwg.org/multipage/semantics.html#attr-meta-http-equiv-refresh): Refresh state: the shared declarative refresh steps, and the authoring conformance requirement this subject enforces — the only sentence in HTML that says what a conforming value looks like

## Configuration

```toml
[violations.refresh_value_malformed]
# A Refresh value is neither of the two forms
severity = "warn"
```

## Reported By

- [refresh_header_syntax](../rules/refresh_header_syntax.md)
