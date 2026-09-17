<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cache_control_private_ignored

A validator from a private response reaches a second client

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9111 §5.2.2.7](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.7): private — the unqualified form's prohibition on a shared cache storing the response at all, the argument syntax `#field-name`, the qualified form defined as an argument listing one or more field names, and the Note that caches often handle it as an unqualified private

## Configuration

```toml
[violations.cache_control_private_ignored]
# A validator from a private response reaches a second client
severity = "warn"
```

## Reported By

- [private_cache_visibility](../rules/private_cache_visibility.md)
