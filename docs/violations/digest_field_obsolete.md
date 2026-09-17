<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# digest_field_obsolete

Digest or Want-Digest is a field RFC 9530 retired

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html): Digest Fields, which obsoletes RFC 3230 and the `Digest` and `Want-Digest` fields with it — the sentence that makes a well-formed legacy field a finding rather than a style preference

## Configuration

```toml
[violations.digest_field_obsolete]
# Digest or Want-Digest is a field RFC 9530 retired
severity = "warn"
```

## Reported By

- [digest_header_syntax](../rules/digest_header_syntax.md)
