<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# x_content_type_options_missing

A response does not ask for its content type to be respected

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [Fetch §3.6](https://fetch.spec.whatwg.org/#x-content-type-options-header): `X-Content-Type-Options`: the conformance value ABNF (`"nosniff" ; case-insensitive`) and the determine-nosniff algorithm

## Configuration

```toml
[violations.x_content_type_options_missing]
# A response does not ask for its content type to be respected
severity = "info"
```

## Reported By

- [x_content_type_options_present](../rules/x_content_type_options_present.md)
