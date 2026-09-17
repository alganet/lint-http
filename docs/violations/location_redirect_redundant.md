<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# location_redirect_redundant

A redirect names the target URI of the request it answers

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §15.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4): Redirection 3xx: a client SHOULD detect and intervene in cyclical redirections, and MAY follow a Location even where the specific status code is not understood

## Configuration

```toml
[violations.location_redirect_redundant]
# A redirect names the target URI of the request it answers
severity = "warn"
```

## Reported By

- [redirect_chain_valid](../rules/redirect_chain_valid.md)
