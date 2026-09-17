<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cache_control_redundant

A reuse directive sits on a response no cache may select

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9111 §4.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1): Calculating Cache Keys with the Vary Header Field — a `Vary: *` never matches, so no stored response of that resource can be selected and a directive advertising reuse has nothing to act on

## Configuration

```toml
[violations.cache_control_redundant]
# A reuse directive sits on a response no cache may select
severity = "warn"
```

## Reported By

- [vary_and_cache_consistent](../rules/vary_and_cache_consistent.md)
