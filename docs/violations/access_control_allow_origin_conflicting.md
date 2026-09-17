<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# access_control_allow_origin_conflicting

Access-Control-Allow-Origin echoes an origin that did not ask

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [Fetch §4.10](https://fetch.spec.whatwg.org/#concept-cors-check): Fetch CORS check — `*` succeeds only where the request's credentials mode is not `include`, and every other value is compared against the byte-serialized request origin

## Configuration

```toml
[violations.access_control_allow_origin_conflicting]
# Access-Control-Allow-Origin echoes an origin that did not ask
severity = "warn"
```

## Reported By

- [origin_matching_for_cors](../rules/origin_matching_for_cors.md)
