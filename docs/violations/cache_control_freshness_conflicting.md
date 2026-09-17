<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cache_control_freshness_conflicting

A Cache-Control freshness directive is given more than one value

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9111 §4.2.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.1): Calculating Freshness Lifetime — the order a cache consults `s-maxage`, `max-age` and `Expires` in, and what it may do when one directive is present more than once

## Configuration

```toml
[violations.cache_control_freshness_conflicting]
# A Cache-Control freshness directive is given more than one value
severity = "warn"
```

## Reported By

- [caching_directive_interaction](../rules/caching_directive_interaction.md)
