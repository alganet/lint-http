<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cookie_path_non_ascii_character_forbidden

Set-Cookie Path attribute holds a raw non-ASCII character

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 6265 §4.1.1](https://www.rfc-editor.org/rfc/rfc6265.html#section-4.1.1): Set-Cookie syntax — servers SHOULD NOT send a non-conforming Set-Cookie; the `cookie-av` list, where each attribute is written with or without a value, and the `path-value` that excludes control characters and `;`

## Configuration

```toml
[violations.cookie_path_non_ascii_character_forbidden]
# Set-Cookie Path attribute holds a raw non-ASCII character
severity = "warn"
```

## Reported By

- [cookie_path_valid](../rules/cookie_path_valid.md)
