<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# pragma_conflicting

A request asks for no-cache and only-if-cached at once

## Message

Request contains 'Pragma: no-cache' and 'Cache-Control: only-if-cached' which are contradictory

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9111 §5.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.4): Pragma — defined for HTTP/1.0 caches so a client could ask for `no-cache`, superseded by `Cache-Control`, deprecated by this specification, and never given a meaning in a response at all

## Configuration

```toml
[violations.pragma_conflicting]
# A request asks for no-cache and only-if-cached at once
severity = "warn"
```

## Reported By

- [cache_control_and_pragma_consistent](../rules/cache_control_and_pragma_consistent.md)
