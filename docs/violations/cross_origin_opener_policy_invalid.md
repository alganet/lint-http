<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cross_origin_opener_policy_invalid

Cross-Origin-Opener-Policy names no opener policy

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [HTML §7.1.3.1](https://html.spec.whatwg.org/multipage/browsers.html#the-coop-headers): The `Cross-Origin-Opener-Policy` header is parsed as a single structured-field item (token); `same-origin-plus-COEP` is derived from `same-origin` + a compatible COEP, never set directly

## Configuration

```toml
[violations.cross_origin_opener_policy_invalid]
# Cross-Origin-Opener-Policy names no opener policy
severity = "warn"
```

## Reported By

- [cross_origin_opener_policy_valid](../rules/cross_origin_opener_policy_valid.md)
