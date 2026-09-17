<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# challenge_token68_invalid

Authentication token68 is indistinguishable from a parameter

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Configuration

```toml
[violations.challenge_token68_invalid]
# Authentication token68 is indistinguishable from a parameter
severity = "info"
```

## Reported By

- [www_authenticate_challenge_syntax](../rules/www_authenticate_challenge_syntax.md)
