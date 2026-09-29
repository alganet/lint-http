<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# vary_conflicting

A default response omits a field its siblings name in Vary

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9111 §4.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1): Calculating Cache Keys with the Vary Header Field — a resource whose default response omits Vary has that response chosen for later requests even when a more preferable one is available

## Configuration

```toml
[violations.vary_conflicting]
# A default response omits a field its siblings name in Vary
severity = "warn"
```

## Reported By

- [vary_consistent](../rules/vary_consistent.md)
