<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# strict_transport_security_empty

The policy is written with nothing in it

## Message

Strict-Transport-Security header must not be empty

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Configuration

```toml
[violations.strict_transport_security_empty]
# The policy is written with nothing in it
severity = "warn"
```

## Reported By

- [strict_transport_security_valid](../rules/strict_transport_security_valid.md)
