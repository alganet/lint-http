<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_location_fragment_forbidden

Content-Location carries a fragment component

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.1): URI References — `partial-URI` is the rule for protocol elements carrying a relative URI but no fragment, and an element's own ABNF says which forms of reference it allows

## Configuration

```toml
[violations.content_location_fragment_forbidden]
# Content-Location carries a fragment component
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [content_location_and_uri_consistent](../rules/content_location_and_uri_consistent.md)
