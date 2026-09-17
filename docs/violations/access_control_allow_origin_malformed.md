<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# access_control_allow_origin_malformed

Access-Control-Allow-Origin states a value that is none of `*`, `null` and a serialized origin

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [Fetch §3.3.3](https://fetch.spec.whatwg.org/#http-access-control-allow-origin): `Access-Control-Allow-Origin` carries one value: an echoed origin, `null`, or `*`

## Configuration

```toml
[violations.access_control_allow_origin_malformed]
# Access-Control-Allow-Origin states a value that is none of `*`, `null` and a serialized origin
severity = "warn"
```

## Reported By

- [access_control_allow_origin_valid](../rules/access_control_allow_origin_valid.md)
- [origin_matching_for_cors](../rules/origin_matching_for_cors.md)
