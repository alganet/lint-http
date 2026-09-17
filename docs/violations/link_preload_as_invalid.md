<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# link_preload_as_invalid

A response's preload link names no preload destination in its as

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [HTML Semantics §4.2.4.4](https://html.spec.whatwg.org/multipage/semantics.html#processing-link-headers): *Processing `Link` headers* — the algorithm that reads this field out of a **response** and, for `rel=preload`, returns early when `as` does not exist or names no preload destination. The only published sentences pairing the two, and the reason both findings are worded as a member being discarded rather than as a MUST

## Configuration

```toml
[violations.link_preload_as_invalid]
# A response's preload link names no preload destination in its as
severity = "warn"
```

## Reported By

- [link_header_valid](../rules/link_header_valid.md)
