<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_coding_unregistered

Content coding is not one the deployment recognises

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §8.4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4.1): `content-coding = token`, case-insensitive, and the "ought to be registered" guidance that motivates the rule without being what it checks

## Configuration

```toml
[violations.content_coding_unregistered]
# Content coding is not one the deployment recognises
severity = "warn"
```

## Reported By

- [content_encoding_registered](../rules/content_encoding_registered.md)
