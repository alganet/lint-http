<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# digest_value_malformed

Digest field member's value is not a Byte Sequence

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9530 §2](https://www.rfc-editor.org/rfc/rfc9530.html#section-2): `Content-Digest`: a Dictionary keyed by hashing algorithm whose values are Byte Sequences

## Configuration

```toml
[violations.digest_value_malformed]
# Digest field member's value is not a Byte Sequence
severity = "warn"
```

## Reported By

- [digest_header_syntax](../rules/digest_header_syntax.md)
