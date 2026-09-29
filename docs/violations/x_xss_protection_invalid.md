<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# x_xss_protection_invalid

X-XSS-Protection asks for neither the filter off nor the page blocked

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Configuration

```toml
[violations.x_xss_protection_invalid]
# X-XSS-Protection asks for neither the filter off nor the page blocked
severity = "info"
```

## Reported By

- [x_xss_protection_value_valid](../rules/x_xss_protection_value_valid.md)
