<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# digest_credentials_nc_invalid

A Digest nonce-count is not the number the exchange calls for

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 7616 §3.4](https://www.rfc-editor.org/rfc/rfc7616.html#section-3.4): The Authorization Header Field — the Digest credentials, their parameters, the 4xx consequence for missing or improper ones, the "MUST be used by all implementations" on cnonce and nc, and the two historical-reasons quoting MUSTs enforced in both directions
- [RFC 7616 §3.3](https://www.rfc-editor.org/rfc/rfc7616.html#section-3.3): The WWW-Authenticate Response Header Field — the server challenge, its `nonce` and `opaque` and the case-insensitive `stale` flag a client answers by restarting the count

## Configuration

```toml
[violations.digest_credentials_nc_invalid]
# A Digest nonce-count is not the number the exchange calls for
severity = "warn"
```

## Reported By

- [digest_auth_nonce_handling](../rules/digest_auth_nonce_handling.md)
