<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# well_known_path_invalid

A .well-known segment sits below the top of the path

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 8615 §3](https://www.rfc-editor.org/rfc/rfc8615.html#section-3): Well-Known URIs — the definition and its scheme proviso, the `segment-nz` MUST on a registered name, the MAY for additional path components, and the sentence saying a `.well-known` elsewhere in the path is not one

## Configuration

```toml
[violations.well_known_path_invalid]
# A .well-known segment sits below the top of the path
severity = "info"
```

## Reported By

- [well_known_uri_syntax](../rules/well_known_uri_syntax.md)
