<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# link_type_malformed

Link type attribute does not derive from type-name "/" subtype-name

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 8288 §3.4.1](https://www.rfc-editor.org/rfc/rfc8288.html#section-3.4.1): The four serialisation-defined attributes this document bounds to one occurrence — `media`, `title`, `title*`, `type` — each in its own MUST NOT. `hreflang` is the one it deliberately leaves unbounded, saying that repeating it means several languages are available. Also the per-attribute value ABNFs: `Language-Tag` for `hreflang`, `type-name "/" subtype-name` for `type`, and `media-query-list` for `media` — the first two measured here, the third declined for the reasons the description gives

## Configuration

```toml
[violations.link_type_malformed]
# Link type attribute does not derive from type-name "/" subtype-name
severity = "warn"
```

## Reported By

- [link_header_valid](../rules/link_header_valid.md)
