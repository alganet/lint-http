<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cookie_max_age_malformed

Set-Cookie Max-Age is not a number a user agent will read

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 6265 §5.2.2](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.2): The Max-Age attribute — ignored unless it is a `-`-or-DIGIT first character with an all-DIGIT remainder

## Configuration

```toml
[violations.cookie_max_age_malformed]
# Set-Cookie Max-Age is not a number a user agent will read
severity = "warn"
```

## Reported By

- [cookie_attribute_consistent](../rules/cookie_attribute_consistent.md)
