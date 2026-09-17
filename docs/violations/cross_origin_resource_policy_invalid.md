<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cross_origin_resource_policy_invalid

Cross-Origin-Resource-Policy names no resource policy

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [Fetch §3.7](https://fetch.spec.whatwg.org/#cross-origin-resource-policy-header): `Cross-Origin-Resource-Policy` — the case-sensitive `same-origin`/`same-site`/`cross-origin` grammar, and unrecognized values set to null

## Configuration

```toml
[violations.cross_origin_resource_policy_invalid]
# Cross-Origin-Resource-Policy names no resource policy
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [cross_origin_resource_policy_valid](../rules/cross_origin_resource_policy_valid.md)
