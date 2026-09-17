<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# etag_wildcard_forbidden

An ETag carries the wildcard the conditional fields take

## Message

ETag header value '*' is invalid for responses; ETag must be an entity-tag

## Specifications

- [RFC 9110 §8.8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3): Entity Tags — `entity-tag = [ weak ] opaque-tag`, `weak = %s"W/"` (case-sensitive by the `%s` prefix), `opaque-tag = DQUOTE *etagc DQUOTE`, and `etagc` as VCHAR minus the DQUOTE plus obs-text

## Configuration

```toml
[violations.etag_wildcard_forbidden]
# An ETag carries the wildcard the conditional fields take
severity = "warn"
```

## Reported By

- [etag_syntax](../rules/etag_syntax.md)
