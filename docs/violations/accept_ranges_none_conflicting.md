<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# accept_ranges_none_conflicting

Accept-Ranges says 'none' where range requests demonstrably work

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §14.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.3): `Accept-Ranges`: `acceptable-ranges = 1#range-unit`, what advertising a unit is for, the reservation of `none` for a server supporting no kind of range request, and the MAYs on both sides that make every finding here advice rather than a broken requirement

## Configuration

```toml
[violations.accept_ranges_none_conflicting]
# Accept-Ranges says 'none' where range requests demonstrably work
severity = "warn"
```

## Reported By

- [accept_ranges_and_206_consistent](../rules/accept_ranges_and_206_consistent.md)
- [accept_ranges_values_valid](../rules/accept_ranges_values_valid.md)
