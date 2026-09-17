<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# referer_fragment_forbidden

A Referer carries a fragment component

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §10.1.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.3): Referer — the field's grammar, the fragment and userinfo MUST NOT, the unsecured-request MUST NOT, and the two declined conditionals

## Configuration

```toml
[violations.referer_fragment_forbidden]
# A Referer carries a fragment component
severity = "warn"
```

## Reported By

- [referer_uri_valid](../rules/referer_uri_valid.md)
