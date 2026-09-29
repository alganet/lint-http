<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# etag_conflicting

One strong entity tag names two content codings

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §8.8.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.1): Weak versus Strong — a validator shared by two representations of a resource at the same time is weak unless their data is identical, and a gzip-coded and an unencoded representation are the example
- [RFC 9110 §8.8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3): Entity Tags — `entity-tag = [ weak ] opaque-tag`, `weak = %s"W/"` (case-sensitive by the `%s` prefix), `opaque-tag = DQUOTE *etagc DQUOTE`, and `etagc` as VCHAR minus the DQUOTE plus obs-text

## Configuration

```toml
[violations.etag_conflicting]
# One strong entity tag names two content codings
severity = "warn"
```

## Reported By

- [etag_and_content_encoding_consistent](../rules/etag_and_content_encoding_consistent.md)
