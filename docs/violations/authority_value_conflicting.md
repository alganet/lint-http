<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# authority_value_conflicting

An :authority and Host are one authority in two spellings

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9114 §4.3.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.1): Request Pseudo-Header Fields — the exactly-one MUST for `:method`, `:scheme` and `:path`, the `:authority`-or-Host requirement for schemes with a mandatory authority component, and the MUST NOT on the deprecated userinfo subcomponent for http and https URIs

## Configuration

```toml
[violations.authority_value_conflicting]
# An :authority and Host are one authority in two spellings
severity = "warn"
```

## Reported By

- [host_and_authority_consistent](../rules/host_and_authority_consistent.md)
