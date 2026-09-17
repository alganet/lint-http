<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# refresh_url_empty

A Refresh value writes URL= with no URL

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [HTML Semantics §4.2.5.3](https://html.spec.whatwg.org/multipage/semantics.html#attr-meta-http-equiv-refresh): Refresh state: the shared declarative refresh steps, and the authoring conformance requirement this subject enforces — the only sentence in HTML that says what a conforming value looks like

## Configuration

```toml
[violations.refresh_url_empty]
# A Refresh value writes URL= with no URL
severity = "warn"
```

## Reported By

- [refresh_header_syntax](../rules/refresh_header_syntax.md)
