<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# media_type_suffix_unregistered

A structured syntax suffix is not one the deployment recognises

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 6838 §4.2.8](https://www.rfc-editor.org/rfc/rfc6838.html#section-4.2.8): Structured Syntax Name Suffixes: that an unregistered `+suffix` SHOULD NOT be used, and — the sharper half — that a suffix MUST NOT name a syntax the type does not employ

## Configuration

```toml
[violations.media_type_suffix_unregistered]
# A structured syntax suffix is not one the deployment recognises
severity = "warn"
```

## Reported By

- [media_type_suffix_valid](../rules/media_type_suffix_valid.md)
