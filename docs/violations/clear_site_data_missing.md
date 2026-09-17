<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# clear_site_data_missing

A sign-out response does not ask the client to clear its storage

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [Clear-Site-Data §3.1](https://www.w3.org/TR/clear-site-data/#header): The `Clear-Site-Data` HTTP response header field (its purpose; §1.1.1 is the sign-out example this finding encodes)

## Configuration

```toml
[violations.clear_site_data_missing]
# A sign-out response does not ask the client to clear its storage
severity = "info"
```

## Reported By

- [clear_site_data_present](../rules/clear_site_data_present.md)
