<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# digest_equals_missing

Digest member is written without its '='

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 3230 §4.2](https://www.rfc-editor.org/rfc/rfc3230.html#section-4.2): Instance digests: `instance-digest = digest-algorithm "=" <encoded digest output>`, the production a legacy `Digest` member is written in — three parts with nothing bracketed, and an encoding the algorithm's own definition supplies

## Configuration

```toml
[violations.digest_equals_missing]
# Digest member is written without its '='
severity = "warn"
```

## Reported By

- [digest_header_syntax](../rules/digest_header_syntax.md)
