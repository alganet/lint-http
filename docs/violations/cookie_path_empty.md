<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cookie_path_empty

Set-Cookie Path attribute is empty

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 6265 §5.2.4](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.4): Path attribute — the user agent replaces an empty or non-`/` Path with the default-path (why those forms are flagged)

## Configuration

```toml
[violations.cookie_path_empty]
# Set-Cookie Path attribute is empty
severity = "warn"
```

## Reported By

- [cookie_path_valid](../rules/cookie_path_valid.md)
