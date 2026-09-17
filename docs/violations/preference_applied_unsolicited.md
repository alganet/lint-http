<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# preference_applied_unsolicited

A Preference-Applied names a preference nobody asked for

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 7240 §3](https://www.rfc-editor.org/rfc/rfc7240.html#section-3): `Preference-Applied` — the field's definition, its grammar, and the sentence saying it is the `Prefer` grammar without parameters

## Configuration

```toml
[violations.preference_applied_unsolicited]
# A Preference-Applied names a preference nobody asked for
severity = "warn"
```

## Reported By

- [preference_applied_header_valid](../rules/preference_applied_header_valid.md)
