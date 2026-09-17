<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cross_origin_embedder_policy_invalid

Cross-Origin-Embedder-Policy names no embedder policy

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [HTML §7.1.4](https://html.spec.whatwg.org/multipage/browsers.html#cross-origin-embedder-policy): The `Cross-Origin-Embedder-Policy` header — its value is one of the three embedder policy strings `unsafe-none`, `require-corp`, `credentialless`

## Configuration

```toml
[violations.cross_origin_embedder_policy_invalid]
# Cross-Origin-Embedder-Policy names no embedder policy
severity = "warn"
```

## Reported By

- [cross_origin_embedder_policy_valid](../rules/cross_origin_embedder_policy_valid.md)
