<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# vary_ignored

A response is reused across a dimension its Vary nominated

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9111 §4.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1): Calculating Cache Keys with the Vary Header Field — a stored response may only be reused without revalidation where every request field the response nominated matches the original request's

## Configuration

```toml
[violations.vary_ignored]
# A response is reused across a dimension its Vary nominated
severity = "warn"
```

## Reported By

- [vary_header_cache_valid](../rules/vary_header_cache_valid.md)
