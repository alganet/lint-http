<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# challenge_realm_ambiguous

One realm is advertised by two authentication schemes

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §11.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.5): Establishing a Protection Space (Realm) — a realm names one protection space, each with its own authentication scheme, and a response may carry several challenges of one scheme with different realms

## Configuration

```toml
[violations.challenge_realm_ambiguous]
# One realm is advertised by two authentication schemes
severity = "warn"
```

## Reported By

- [authentication_challenge_valid](../rules/authentication_challenge_valid.md)
