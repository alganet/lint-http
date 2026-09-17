<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# server_timing_dur_invalid

Server-Timing writes a dur that is not a valid floating-point number

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Configuration

```toml
[violations.server_timing_dur_invalid]
# Server-Timing writes a dur that is not a valid floating-point number
severity = "info"
```

## Reported By

- [server_timing_header_syntax](../rules/server_timing_header_syntax.md)
