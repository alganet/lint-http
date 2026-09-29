<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# charset_unregistered

A charset name is not in the IANA registry

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §8.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.2): Charset: what the parameter means, that names are matched case-insensitively, and the "ought to be registered" guidance that motivates this rule — guidance, not a requirement, and not something this rule verifies

## Configuration

```toml
[violations.charset_unregistered]
# A charset name is not in the IANA registry
severity = "warn"
```

## Reported By

- [charset_registered](../rules/charset_registered.md)
