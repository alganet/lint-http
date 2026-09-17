<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# forwarded_parameter_duplicated

Forwarded element names one parameter more than once

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 7239 §4](https://www.rfc-editor.org/rfc/rfc7239.html#section-4): The field's grammar, the case-insensitivity of parameter names, the MUST NOT on naming a parameter twice in one element, and the sentence restricting the field to requests

## Configuration

```toml
[violations.forwarded_parameter_duplicated]
# Forwarded element names one parameter more than once
severity = "warn"
```

## Reported By

- [forwarded_header_valid](../rules/forwarded_header_valid.md)
