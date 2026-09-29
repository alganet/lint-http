<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# access_control_allow_credentials_conflicting

Access-Control-Allow-Credentials claims `true` beside a wildcard origin

## Message

Access-Control-Allow-Credentials is 'true' beside Access-Control-Allow-Origin '*', and the 'true' turns nothing on: the CORS check shares on the wildcard only with a request that carries no credentials, never reading this field for it, and refuses a credentialed request on the wildcard. To share with credentials, answer with the requesting origin in place of '*'; otherwise delete this line

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

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
