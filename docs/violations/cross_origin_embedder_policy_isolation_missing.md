<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cross_origin_embedder_policy_isolation_missing

A Cross-Origin-Embedder-Policy is set to the value that does not isolate

## Message

Cross-Origin-Embedder-Policy is 'unsafe-none', which is valid and does not enable cross-origin isolation (use 'require-corp' or 'credentialless')

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Configuration

```toml
[violations.cross_origin_embedder_policy_isolation_missing]
# A Cross-Origin-Embedder-Policy is set to the value that does not isolate
severity = "info"
```

## Reported By

- [cross_origin_embedder_policy_valid](../rules/cross_origin_embedder_policy_valid.md)
