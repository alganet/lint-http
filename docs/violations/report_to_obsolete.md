<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# report_to_obsolete

A response declares its endpoint groups in a field that has been replaced

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [MDN Report-To](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Report-To): Report-To — a response header marked Deprecated and Non-standard, replaced by `Reporting-Endpoints`, whose value is one or more endpoint-group definitions written as a JSON array with the surrounding brackets omitted
- [Network Error Logging §4.1.1](https://www.w3.org/TR/network-error-logging/#the-report_to-member): The report_to member — REQUIRED to register a NEL policy, OPTIONAL to remove one, and a MUST that its value is a string

## Configuration

```toml
[violations.report_to_obsolete]
# A response declares its endpoint groups in a field that has been replaced
severity = "info"
```

## Reported By

- [report_to_groups_valid](../rules/report_to_groups_valid.md)
