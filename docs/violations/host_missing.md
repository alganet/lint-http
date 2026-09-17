<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# host_missing

A request names its authority in neither Host nor :authority

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §7.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2): Host and :authority — `Host = uri-host [ ":" port ]`, the MUST to generate the field, and the `:authority` pseudo-header the MUST excepts

## Configuration

```toml
[violations.host_missing]
# A request names its authority in neither Host nor :authority
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [host_header](../rules/host_header.md)
