<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_md5_redundant

A message carries two integrity values over one content

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Configuration

```toml
[violations.content_md5_redundant]
# A message carries two integrity values over one content
severity = "info"
```

## Reported By

- [content_md5_vs_digest_preference](../rules/content_md5_vs_digest_preference.md)
