<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# etag_delimiter_missing

Entity-tag is not quoted

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §8.8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3): Entity Tags — `entity-tag = [ weak ] opaque-tag`, `weak = %s"W/"` (case-sensitive by the `%s` prefix), `opaque-tag = DQUOTE *etagc DQUOTE`, and `etagc` as VCHAR minus the DQUOTE plus obs-text

## Configuration

```toml
[violations.etag_delimiter_missing]
# Entity-tag is not quoted
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [conditional_etag_syntax](../rules/conditional_etag_syntax.md)
- [conditional_headers_consistent](../rules/conditional_headers_consistent.md)
- [etag_syntax](../rules/etag_syntax.md)
