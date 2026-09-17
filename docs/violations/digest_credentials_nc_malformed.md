<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# digest_credentials_nc_malformed

A Digest nonce-count is not eight hexadecimal digits

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 7616 §3.5](https://www.rfc-editor.org/rfc/rfc7616.html#section-3.5): The Authentication-Info Header Field — where the nc value's width is written down; § 3.4 introduces `nc` as "the hexadecimal count" and never fixes it, and this section requires the field's nc to be the client's, so it is one value with one width

## Configuration

```toml
[violations.digest_credentials_nc_malformed]
# A Digest nonce-count is not eight hexadecimal digits
severity = "warn"
```

## Reported By

- [digest_auth_nonce_handling](../rules/digest_auth_nonce_handling.md)
