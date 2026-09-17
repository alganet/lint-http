<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_location_fragment_forbidden

Content-Location carries a fragment component

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.1): URI References — `partial-URI` is the rule for protocol elements carrying a relative URI but no fragment, and an element's own ABNF says which forms of reference it allows

## Configuration

```toml
[violations.content_location_fragment_forbidden]
# Content-Location carries a fragment component
severity = "warn"
```

## Reported By

- [content_location_and_uri_consistent](../rules/content_location_and_uri_consistent.md)
