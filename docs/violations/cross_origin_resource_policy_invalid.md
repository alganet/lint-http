<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cross_origin_resource_policy_invalid

Cross-Origin-Resource-Policy names no resource policy

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [Fetch §3.7](https://fetch.spec.whatwg.org/#cross-origin-resource-policy-header): `Cross-Origin-Resource-Policy` — the case-sensitive `same-origin`/`same-site`/`cross-origin` grammar, and unrecognized values set to null

## Configuration

```toml
[violations.cross_origin_resource_policy_invalid]
# Cross-Origin-Resource-Policy names no resource policy
severity = "warn"
```

## Reported By

- [cross_origin_resource_policy_valid](../rules/cross_origin_resource_policy_valid.md)
