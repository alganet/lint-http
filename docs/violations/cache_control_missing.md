<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cache_control_missing

A heuristically cacheable response leaves its freshness lifetime to be guessed

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9111 §4.2.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.2): Calculating Heuristic Freshness — without an explicit expiration time a cache MAY assign one of its own, estimated from other field values

## Configuration

```toml
[violations.cache_control_missing]
# A heuristically cacheable response leaves its freshness lifetime to be guessed
severity = "info"
```

## Reported By

- [cache_control_present](../rules/cache_control_present.md)
