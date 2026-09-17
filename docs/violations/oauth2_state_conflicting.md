<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# oauth2_state_conflicting

A callback's state matches no request that was seen

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 6749 §4.1.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.1): Authorization Request — response_type MUST be "code"; the state parameter is RECOMMENDED

## Configuration

```toml
[violations.oauth2_state_conflicting]
# A callback's state matches no request that was seen
severity = "warn"
```

## Reported By

- [oauth2_code_flow](../rules/oauth2_code_flow.md)
