<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# priority_cacheability_missing

A Priority response says nothing about caching

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9218 §5](https://www.rfc-editor.org/rfc/rfc9218.html#section-5): The `Priority` response header field — an end-to-end signal a server may generate from properties of the request, and the expectation that a server doing so also controls the cacheability of what it sends

## Configuration

```toml
[violations.priority_cacheability_missing]
# A Priority response says nothing about caching
severity = "warn"
```

## Reported By

- [priority_and_cacheability_consistent](../rules/priority_and_cacheability_consistent.md)
