<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# refresh_url_malformed

A Refresh URL is not a valid URL string

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [URL §4.3](https://url.spec.whatwg.org/#url-writing): URL writing: valid URL string, URL code points and URL units — the alphabet the `URL=` value is judged against, which is not RFC 3986's

## Configuration

```toml
[violations.refresh_url_malformed]
# A Refresh URL is not a valid URL string
severity = "warn"
```

## Reported By

- [refresh_header_syntax](../rules/refresh_header_syntax.md)
