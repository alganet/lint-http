<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# early_data_method_forbidden

A request in early data uses a method whose safety is not known

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 8470 §4](https://www.rfc-editor.org/rfc/rfc8470.html#section-4): Using Early Data in HTTP Clients — the MUST NOT covering unsafe methods and methods whose safety is not known, opening with an "Absent other information" no message records

## Configuration

```toml
[violations.early_data_method_forbidden]
# A request in early data uses a method whose safety is not known
severity = "warn"
```

## Reported By

- [early_data_header_safe_method](../rules/early_data_header_safe_method.md)
