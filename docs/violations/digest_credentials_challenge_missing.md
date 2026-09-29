<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# digest_credentials_challenge_missing

Digest credentials name a nonce no observed challenge offered

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Configuration

```toml
[violations.digest_credentials_challenge_missing]
# Digest credentials name a nonce no observed challenge offered
severity = "info"
```

## Reported By

- [digest_auth_nonce_handling](../rules/digest_auth_nonce_handling.md)
