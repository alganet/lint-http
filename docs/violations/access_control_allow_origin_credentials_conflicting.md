<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# access_control_allow_origin_credentials_conflicting

The wildcard origin sits on a response that also allows credentials

## Message

Access-Control-Allow-Origin '*' is not allowed when Access-Control-Allow-Credentials is true

## Specifications

- [Fetch §4.10](https://fetch.spec.whatwg.org/#concept-cors-check): Fetch CORS check — `*` succeeds only where the request's credentials mode is not `include`, and every other value is compared against the byte-serialized request origin

## Configuration

```toml
[violations.access_control_allow_origin_credentials_conflicting]
# The wildcard origin sits on a response that also allows credentials
severity = "warn"
```

## Reported By

- [origin_matching_for_cors](../rules/origin_matching_for_cors.md)
