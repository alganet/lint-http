<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# method_options_allow_conflicting

A successful OPTIONS advertises methods and leaves out the one it answered

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §10.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.1): `Allow` lists the methods advertised as supported by the target resource, is a MAY on any response other than a 405, and an empty value of it says the resource allows no methods

## Configuration

```toml
[violations.method_options_allow_conflicting]
# A successful OPTIONS advertises methods and leaves out the one it answered
severity = "info"
```

## Reported By

- [options_method_capabilities](../rules/options_method_capabilities.md)
