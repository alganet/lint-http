<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# accept_charset_obsolete

A request carries a field this specification deprecates

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §12.5.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.2): Accept-Charset: `#( ( token / "*" ) [ weight ] )` — the production that says a charset name may carry a weight and nothing else, the meaning given to the `*`, the pointer to §8.3.2 for the names themselves, and the Note that deprecates the field. Like §12.5.4 and unlike §12.5.1 and §12.5.3, it gives the field no meaning in a response

## Configuration

```toml
[violations.accept_charset_obsolete]
# A request carries a field this specification deprecates
severity = "info"
```

## Reported By

- [accept_charset_valid](../rules/accept_charset_valid.md)
