<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# access_control_allow_origin_credentials_conflicting

The wildcard origin sits beside an Access-Control-Allow-Credentials of `true`

## Message

Access-Control-Allow-Origin is '*' beside Access-Control-Allow-Credentials 'true': the wildcard shares this response only with a request that carries no credentials and refuses a credentialed one, so the 'true' turns nothing on. To share with credentials, answer with the requesting origin in place of '*'

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [Fetch §4.10](https://fetch.spec.whatwg.org/#concept-cors-check): Fetch CORS check — `*` succeeds only where the request's credentials mode is not `include`, and every other value is compared against the byte-serialized request origin

## Configuration

```toml
[violations.access_control_allow_origin_credentials_conflicting]
# The wildcard origin sits beside an Access-Control-Allow-Credentials of `true`
severity = "warn"
```

## Reported By

- [origin_matching_for_cors](../rules/origin_matching_for_cors.md)
