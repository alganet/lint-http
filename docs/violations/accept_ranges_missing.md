<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# accept_ranges_missing

A partial response advertises no range units

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §14.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.3): `Accept-Ranges`: `acceptable-ranges = 1#range-unit`, what advertising a unit is for, the reservation of `none` for a server supporting no kind of range request, and the MAYs on both sides that make every finding here advice rather than a broken requirement

## Configuration

```toml
[violations.accept_ranges_missing]
# A partial response advertises no range units
severity = "info"
```

## Reported By

- [accept_ranges_and_206_consistent](../rules/accept_ranges_and_206_consistent.md)
