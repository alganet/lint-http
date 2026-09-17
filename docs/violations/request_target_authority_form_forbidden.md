<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# request_target_authority_form_forbidden

The host-and-port target is sent with a method other than CONNECT

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §7.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1): Determining the Target Resource — the two method-specific forms, the MUST NOT that keeps each to its method, and the reconstruction being specific to each major protocol version

## Configuration

```toml
[violations.request_target_authority_form_forbidden]
# The host-and-port target is sent with a method other than CONNECT
severity = "error"
```

## Reported By

- [request_target_form_valid](../rules/request_target_form_valid.md)
