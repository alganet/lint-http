<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# digest_equals_missing

Digest member is written without its '='

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 3230 §4.2](https://www.rfc-editor.org/rfc/rfc3230.html#section-4.2): Instance digests: `instance-digest = digest-algorithm "=" <encoded digest output>`, the production a legacy `Digest` member is written in — three parts with nothing bracketed, and an encoding the algorithm's own definition supplies

## Configuration

```toml
[violations.digest_equals_missing]
# Digest member is written without its '='
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [digest_header_syntax](../rules/digest_header_syntax.md)
