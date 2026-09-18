<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# access_control_allow_credentials_redundant

Access-Control-Allow-Credentials states the `false` its own absence states

## Message

Access-Control-Allow-Credentials is 'false', which shares nothing with credentials — exactly what omitting the field does; delete the line

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [Fetch §3.3.4](https://fetch.spec.whatwg.org/#http-new-header-syntax): `Access-Control-Allow-Credentials` value ABNF — one literal, byte case-sensitive, among the CORS header productions
- [Fetch §4.10](https://fetch.spec.whatwg.org/#concept-cors-check): Fetch CORS check — `*` succeeds only for non-credentialed requests, so `*` paired with `Access-Control-Allow-Credentials: true` can never authorize a credentialed request (the two cited steps)

## Configuration

```toml
[violations.access_control_allow_credentials_redundant]
# Access-Control-Allow-Credentials states the `false` its own absence states
severity = "info"
```

## Reported By

- [access_control_allow_credentials_when_origin](../rules/access_control_allow_credentials_when_origin.md)
