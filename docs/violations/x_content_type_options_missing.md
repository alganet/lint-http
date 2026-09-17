<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# x_content_type_options_missing

A response does not ask for its content type to be respected

## Message

Missing X-Content-Type-Options: nosniff header

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
