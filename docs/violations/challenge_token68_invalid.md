<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# challenge_token68_invalid

Authentication token68 is indistinguishable from a parameter

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Configuration

```toml
[violations.challenge_token68_invalid]
# Authentication token68 is indistinguishable from a parameter
severity = "info"
```

## Reported By

- [proxy_authenticate_challenge_syntax](../rules/proxy_authenticate_challenge_syntax.md)
- [www_authenticate_challenge_syntax](../rules/www_authenticate_challenge_syntax.md)
