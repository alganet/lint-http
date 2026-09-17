<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# host_missing

A request names its authority in neither Host nor :authority

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §7.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2): Host and :authority — `Host = uri-host [ ":" port ]`, the MUST to generate the field, and the `:authority` pseudo-header the MUST excepts

## Configuration

```toml
[violations.host_missing]
# A request names its authority in neither Host nor :authority
severity = "error"
```

## Reported By

- [host_header](../rules/host_header.md)
