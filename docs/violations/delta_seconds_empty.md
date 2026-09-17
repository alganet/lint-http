<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# delta_seconds_empty

A time in seconds is stated with no digits

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 9111 §1.2.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-1.2.2): `delta-seconds = 1*DIGIT` — the production every field carrying a time in seconds writes its value in, and the clamp that makes an over-long run of digits conforming

## Configuration

```toml
[violations.delta_seconds_empty]
# A time in seconds is stated with no digits
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [age_header_numeric](../rules/age_header_numeric.md)
- [alt_svc_h3_advertisement_valid](../rules/alt_svc_h3_advertisement_valid.md)
- [strict_transport_security_valid](../rules/strict_transport_security_valid.md)
