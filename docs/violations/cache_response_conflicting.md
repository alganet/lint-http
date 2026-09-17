<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cache_response_conflicting

Two responses for one URI disagree about which version is current

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9111 §4.2.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.4): Serving Stale Responses — a cache MUST NOT generate one unless it is disconnected or a client or origin server explicitly permitted it

## Configuration

```toml
[violations.cache_response_conflicting]
# Two responses for one URI disagree about which version is current
severity = "warn"
```

## Reported By

- [cache_coherence](../rules/cache_coherence.md)
