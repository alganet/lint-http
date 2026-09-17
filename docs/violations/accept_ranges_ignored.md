<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# accept_ranges_ignored

A range is requested outside what the resource advertised

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §14.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.2): `Range`: an origin server MUST ignore a `Range` field in a unit it does not understand, which is what a request outside the advertised set is likely to cost — the whole representation instead of the part asked for

## Configuration

```toml
[violations.accept_ranges_ignored]
# A range is requested outside what the resource advertised
severity = "info"
```

## Reported By

- [accept_ranges_on_partial_content](../rules/accept_ranges_on_partial_content.md)
