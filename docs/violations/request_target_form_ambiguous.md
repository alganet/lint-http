<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# request_target_form_ambiguous

A request-target derives from two of the four forms at once

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Configuration

```toml
[violations.request_target_form_ambiguous]
# A request-target derives from two of the four forms at once
severity = "warn"
```

## Reported By

- [request_target_form_valid](../rules/request_target_form_valid.md)
