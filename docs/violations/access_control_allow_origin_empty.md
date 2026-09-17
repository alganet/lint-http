<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# access_control_allow_origin_empty

Access-Control-Allow-Origin is written with no value on it

## Message

Access-Control-Allow-Origin is written with no value

## Specifications

- [Fetch §3.3.3](https://fetch.spec.whatwg.org/#http-access-control-allow-origin): `Access-Control-Allow-Origin` carries one value: an echoed origin, `null`, or `*`

## Configuration

```toml
[violations.access_control_allow_origin_empty]
# Access-Control-Allow-Origin is written with no value on it
severity = "warn"
```

## Reported By

- [access_control_allow_origin_valid](../rules/access_control_allow_origin_valid.md)
