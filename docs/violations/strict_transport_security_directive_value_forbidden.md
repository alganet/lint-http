<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# strict_transport_security_directive_value_forbidden

A valueless directive is written with a value

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 6797 §6.1.2](https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1.2): The includeSubDomains Directive

## Configuration

```toml
[violations.strict_transport_security_directive_value_forbidden]
# A valueless directive is written with a value
severity = "warn"
```

## Reported By

- [strict_transport_security_valid](../rules/strict_transport_security_valid.md)
