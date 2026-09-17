<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cache_control_freshness_missing

A status no cache stores by default states no freshness

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §15.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.1): Overview of Status Codes — the status codes defined as heuristically cacheable, which is the set a response outside it has to state its own freshness to join

## Configuration

```toml
[violations.cache_control_freshness_missing]
# A status no cache stores by default states no freshness
severity = "info"
```

## Reported By

- [status_and_caching_semantics](../rules/status_and_caching_semantics.md)
