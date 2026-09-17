<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# access_control_allow_credentials_conflicting

Access-Control-Allow-Credentials claims `true` beside a wildcard origin

## Message

Access-Control-Allow-Credentials must not be 'true' when Access-Control-Allow-Origin is '*'

## Specifications

- [Fetch §4.10](https://fetch.spec.whatwg.org/#concept-cors-check): Fetch CORS check — `*` succeeds only for non-credentialed requests, so `*` paired with `Access-Control-Allow-Credentials: true` can never authorize a credentialed request (the two cited steps)

## Configuration

```toml
[violations.access_control_allow_credentials_conflicting]
# Access-Control-Allow-Credentials claims `true` beside a wildcard origin
severity = "warn"
```

## Reported By

- [access_control_allow_credentials_when_origin](../rules/access_control_allow_credentials_when_origin.md)
