<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# access_control_allow_credentials_invalid

Access-Control-Allow-Credentials states a value that is not `true`

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [Fetch §4.10](https://fetch.spec.whatwg.org/#concept-cors-check): Fetch CORS check — `*` succeeds only for non-credentialed requests, so `*` paired with `Access-Control-Allow-Credentials: true` can never authorize a credentialed request (the two cited steps)

## Configuration

```toml
[violations.access_control_allow_credentials_invalid]
# Access-Control-Allow-Credentials states a value that is not `true`
severity = "warn"
```

## Reported By

- [access_control_allow_credentials_when_origin](../rules/access_control_allow_credentials_when_origin.md)
