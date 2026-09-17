<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cross_origin_embedder_policy_isolation_missing

A Cross-Origin-Embedder-Policy is set to the value that does not isolate

## Message

Cross-Origin-Embedder-Policy is 'unsafe-none', which is valid and does not enable cross-origin isolation (use 'require-corp' or 'credentialless')

## Configuration

```toml
[violations.cross_origin_embedder_policy_isolation_missing]
# A Cross-Origin-Embedder-Policy is set to the value that does not isolate
severity = "info"
```

## Reported By

- [cross_origin_embedder_policy_valid](../rules/cross_origin_embedder_policy_valid.md)
