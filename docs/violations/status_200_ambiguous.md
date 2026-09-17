<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_200_ambiguous

A 200 carries no content, where a 204 would say so on purpose

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §15.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.1): 200 (OK): a 200 is expected to contain content "unless the message framing explicitly indicates that the content has zero length" — the reported state is that exception, not a breach — and the 204 advice is an "ought to" conditioned on the request preferring no content, which is not observable

## Configuration

```toml
[violations.status_200_ambiguous]
# A 200 carries no content, where a 204 would say so on purpose
severity = "info"
```

## Reported By

- [status_200_vs_204_body_consistent](../rules/status_200_vs_204_body_consistent.md)
