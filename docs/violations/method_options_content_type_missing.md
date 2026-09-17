<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# method_options_content_type_missing

An OPTIONS request carries content without saying what it is

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §9.3.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.7): OPTIONS — the client `MUST` about `Content-Type`, and the `SHOULD` to advertise, which names a class ending "including potential extensions not defined by this specification" rather than a field

## Configuration

```toml
[violations.method_options_content_type_missing]
# An OPTIONS request carries content without saying what it is
severity = "warn"
```

## Reported By

- [options_method_capabilities](../rules/options_method_capabilities.md)
