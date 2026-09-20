<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# referrer_policy_invalid

Referrer-Policy names no referrer policy

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [Referrer Policy §4.1](https://www.w3.org/TR/referrer-policy/#referrer-policy-header): Delivery via Referrer-Policy header — `"Referrer-Policy:" 1#policy-token`, and the eight literals `policy-token` is one of
- [Referrer Policy §8.1](https://www.w3.org/TR/referrer-policy/#parse-referrer-policy-from-header): Parse a referrer policy from a Referrer-Policy header — unknown tokens are ignored, the last recognised one wins, and a field with none of them yields the empty string

## Configuration

```toml
[violations.referrer_policy_invalid]
# Referrer-Policy names no referrer policy
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [referrer_policy_valid](../rules/referrer_policy_valid.md)
