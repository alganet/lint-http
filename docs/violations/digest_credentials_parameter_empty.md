<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# digest_credentials_parameter_empty

A required Digest parameter is written with nothing in it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 7616 §3.4](https://www.rfc-editor.org/rfc/rfc7616.html#section-3.4): The Authorization Header Field — the Digest credentials, their parameters, the 4xx consequence for missing or improper ones, the "MUST be used by all implementations" on cnonce and nc, and the two historical-reasons quoting MUSTs enforced in both directions

## Configuration

```toml
[violations.digest_credentials_parameter_empty]
# A required Digest parameter is written with nothing in it
severity = "warn"
```

## Reported By

- [digest_auth_valid](../rules/digest_auth_valid.md)
