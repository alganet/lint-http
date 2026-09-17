<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# etag_character_forbidden

Entity-tag holds a character etagc does not admit

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §8.8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3): Entity Tags — `entity-tag = [ weak ] opaque-tag`, `weak = %s"W/"` (case-sensitive by the `%s` prefix), `opaque-tag = DQUOTE *etagc DQUOTE`, and `etagc` as VCHAR minus the DQUOTE plus obs-text

## Configuration

```toml
[violations.etag_character_forbidden]
# Entity-tag holds a character etagc does not admit
severity = "warn"
```

## Reported By

- [conditional_etag_syntax](../rules/conditional_etag_syntax.md)
- [conditional_headers_consistent](../rules/conditional_headers_consistent.md)
- [etag_syntax](../rules/etag_syntax.md)
