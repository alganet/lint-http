<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# well_known_prefix_malformed

A path stops one character short of the reserved prefix

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 8615 §1](https://www.rfc-editor.org/rfc/rfc8615.html#section-1): Introduction — the prefix this memo reserves, trailing slash included; that other schemes carry well-known URIs only where their definitions allow it; and the origin's control over its own URI space

## Configuration

```toml
[violations.well_known_prefix_malformed]
# A path stops one character short of the reserved prefix
severity = "info"
```

## Reported By

- [well_known_uri_syntax](../rules/well_known_uri_syntax.md)
