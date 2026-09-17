<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# digest_credentials_quoting_invalid

A Digest parameter is written in the syntax its definition refuses

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 7616 §3.4](https://www.rfc-editor.org/rfc/rfc7616.html#section-3.4): The Authorization Header Field — the Digest credentials, their parameters, the 4xx consequence for missing or improper ones, the "MUST be used by all implementations" on cnonce and nc, and the two historical-reasons quoting MUSTs enforced in both directions

## Configuration

```toml
[violations.digest_credentials_quoting_invalid]
# A Digest parameter is written in the syntax its definition refuses
severity = "warn"
```

## Reported By

- [digest_auth_valid](../rules/digest_auth_valid.md)
