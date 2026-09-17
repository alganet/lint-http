<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# x_content_type_options_invalid

X-Content-Type-Options carries a value that is not nosniff

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [Fetch §3.6](https://fetch.spec.whatwg.org/#x-content-type-options-header): `X-Content-Type-Options`: the conformance value ABNF (`"nosniff" ; case-insensitive`) and the determine-nosniff algorithm

## Configuration

```toml
[violations.x_content_type_options_invalid]
# X-Content-Type-Options carries a value that is not nosniff
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [x_content_type_options_present](../rules/x_content_type_options_present.md)
