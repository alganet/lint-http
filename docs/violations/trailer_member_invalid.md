<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# trailer_member_invalid

A Trailer declaration names a field that cannot arrive

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §6.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.6.2): `Trailer = #field-name` — the list a sender is asked to write so a recipient can prepare for the metadata before it starts processing the content, and the note that the list is a hint rather than a promise

## Configuration

```toml
[violations.trailer_member_invalid]
# A Trailer declaration names a field that cannot arrive
severity = "info"
```

## Reported By

- [trailer_header_valid](../rules/trailer_header_valid.md)
