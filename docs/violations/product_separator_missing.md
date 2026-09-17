<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# product_separator_missing

A product list writes no whitespace between two elements

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §5.6.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.3): Whitespace — `RWS = 1*( SP / HTAB )`, used where at least one linear whitespace octet is *required* to separate field tokens, as opposed to the `OWS` a sender may omit

## Configuration

```toml
[violations.product_separator_missing]
# A product list writes no whitespace between two elements
severity = "warn"
```

## Reported By

- [server_header_product_valid](../rules/server_header_product_valid.md)
- [user_agent_token_valid](../rules/user_agent_token_valid.md)
